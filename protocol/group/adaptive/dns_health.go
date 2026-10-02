package adaptive

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"golang.org/x/net/dns/dnsmessage"
)

var dnsHealthTargets = map[string][]M.Socksaddr{
	"ipv4": {M.ParseSocksaddr("8.8.8.8:53"), M.ParseSocksaddr("1.1.1.1:53")},
	"ipv6": {M.ParseSocksaddr("[2001:4860:4860::8888]:53"), M.ParseSocksaddr("[2606:4700:4700::1111]:53")},
}

const dnsHealthQuestionName = "www.google.com."

func buildDNSHealthQuery() ([]byte, uint16, dnsmessage.Question, error) {
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	id := binary.BigEndian.Uint16(randomID[:])
	name, err := dnsmessage.NewName(dnsHealthQuestionName)
	if err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	question := dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err = builder.StartQuestions(); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	if err = builder.Question(question); err != nil {
		return nil, 0, dnsmessage.Question{}, err
	}
	message, err := builder.Finish()
	return message, id, question, err
}

func validateDNSHealthResponse(message []byte, id uint16, expected dnsmessage.Question) error {
	var parser dnsmessage.Parser
	header, err := parser.Start(message)
	if err != nil {
		return fmt.Errorf("parse DNS header: %w", err)
	}
	if !header.Response || header.ID != id || header.RCode != dnsmessage.RCodeSuccess {
		return fmt.Errorf("unexpected DNS response header: response=%t id=%d rcode=%s", header.Response, header.ID, header.RCode)
	}
	question, err := parser.Question()
	if err != nil {
		return fmt.Errorf("parse DNS question: %w", err)
	}
	if question != expected {
		return errors.New("DNS response question mismatch")
	}
	return nil
}

func runDNSHealthQuery(ctx context.Context, dialer N.Dialer, target M.Socksaddr) error {
	message, id, question, err := buildDNSHealthQuery()
	if err != nil {
		return err
	}
	packetConn, err := dialer.ListenPacket(ctx, target)
	if err != nil {
		return err
	}
	defer packetConn.Close()
	deadline := time.Now().Add(2 * time.Second)
	if contextDeadline, loaded := ctx.Deadline(); loaded && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err = packetConn.SetDeadline(deadline); err != nil {
		return err
	}
	if _, err = packetConn.WriteTo(message, target.UDPAddr()); err != nil {
		return err
	}
	response := make([]byte, 4096)
	count, _, err := packetConn.ReadFrom(response)
	if err != nil {
		return err
	}
	return validateDNSHealthResponse(response[:count], id, question)
}

func runDNSHealthTargets(ctx context.Context, dialer N.Dialer, family string) error {
	targets := dnsHealthTargets[family]
	if len(targets) < 2 {
		return errors.New("DNS health target set is incomplete")
	}
	var failures []error
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runDNSHealthQuery(ctx, dialer, target); err == nil {
			return nil
		} else {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
