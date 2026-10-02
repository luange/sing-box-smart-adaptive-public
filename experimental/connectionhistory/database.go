//go:build with_connection_history

package connectionhistory

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/klauspost/compress/zstd"
)

const (
	segmentMagic        = "SBH2"
	defaultSegmentSize  = int64(8 << 20)
	defaultMaxDiskSize  = int64(256 << 20)
	maxHistoryFrameSize = uint32(64 << 20)
)

type aggregate struct {
	Hour        bool   `json:"h,omitempty"`
	Bucket      int64  `json:"t"`
	Domain      string `json:"d,omitempty"`
	IP          string `json:"i,omitempty"`
	Source      string `json:"s,omitempty"`
	Outbound    string `json:"o,omitempty"`
	Rule        string `json:"r,omitempty"`
	Upload      int64  `json:"u"`
	Download    int64  `json:"n"`
	Connections int64  `json:"c"`
}

type aggregateKey struct {
	Hour     bool
	Bucket   int64
	Domain   string
	IP       string
	Source   string
	Outbound string
	Rule     string
}

type segmentBlock struct {
	Records    []Record    `json:"r,omitempty"`
	Aggregates []aggregate `json:"a,omitempty"`
}

type segmentWriter struct {
	kind    string
	file    *os.File
	path    string
	created int64
	size    int64
}

// database is an append-only immutable-segment store. It avoids mmap and
// copy-on-write page churn; expiry unlinks complete files in O(1).
type database struct {
	access             sync.RWMutex
	dir                string
	segmentSize        int64
	maxDiskSize        int64
	detailRetention    time.Duration
	aggregateRetention time.Duration
	pruneCutoff        atomic.Int64
	sequence           uint64
	detail             segmentWriter
	aggregate          segmentWriter
	encoder            *zstd.Encoder
	decoder            *zstd.Decoder
}

func openDatabase(_ any, path string) (*database, error) {
	return openSegmentDatabase(path, 6*time.Hour, 30*24*time.Hour, defaultSegmentSize, defaultMaxDiskSize)
}

func openSegmentDatabase(path string, detailRetention, aggregateRetention time.Duration, segmentSize, maxDiskSize int64) (*database, error) {
	if detailRetention <= 0 {
		detailRetention = 6 * time.Hour
	}
	if aggregateRetention <= 0 {
		aggregateRetention = 30 * 24 * time.Hour
	}
	if segmentSize <= 0 {
		segmentSize = defaultSegmentSize
	}
	if maxDiskSize <= 0 {
		maxDiskSize = defaultMaxDiskSize
	}
	dir := path + ".segments"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest), zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true))
	if err != nil {
		encoder.Close()
		return nil, err
	}
	return &database{
		dir: dir, segmentSize: segmentSize, maxDiskSize: maxDiskSize,
		detailRetention: detailRetention, aggregateRetention: aggregateRetention,
		encoder: encoder, decoder: decoder,
	}, nil
}

func (d *database) Close() error {
	d.access.Lock()
	defer d.access.Unlock()
	var result error
	for _, writer := range []*segmentWriter{&d.detail, &d.aggregate} {
		if writer.file != nil {
			result = errors.Join(result, writer.file.Sync(), writer.file.Close())
			writer.file = nil
		}
	}
	d.encoder.Close()
	d.decoder.Close()
	return result
}

func (d *database) Size() int64 {
	d.access.RLock()
	defer d.access.RUnlock()
	files, _ := os.ReadDir(d.dir)
	var size int64
	for _, entry := range files {
		if info, err := entry.Info(); err == nil {
			size += info.Size()
		}
	}
	return size
}

func (d *database) SegmentCount() int {
	d.access.RLock()
	defer d.access.RUnlock()
	files, _ := d.segmentFilesLocked()
	return len(files)
}

func (d *database) Write(records []Record, updates map[aggregateKey]aggregate) error {
	d.access.Lock()
	defer d.access.Unlock()
	if len(records) > 0 {
		if err := d.appendBlock(&d.detail, segmentBlock{Records: append([]Record(nil), records...)}); err != nil {
			return err
		}
	}
	if len(updates) > 0 {
		aggregates := make([]aggregate, 0, len(updates))
		for _, item := range updates {
			aggregates = append(aggregates, item)
		}
		if err := d.appendBlock(&d.aggregate, segmentBlock{Aggregates: aggregates}); err != nil {
			return err
		}
	}
	return d.enforceLimitLocked()
}

func (d *database) appendBlock(writer *segmentWriter, block segmentBlock) error {
	payload, err := json.Marshal(block)
	if err != nil {
		return err
	}
	compressed := d.encoder.EncodeAll(payload, nil)
	frameSize := int64(8 + len(compressed))
	if writer.file == nil || writer.size+frameSize > d.segmentSize {
		if err = d.rotate(writer); err != nil {
			return err
		}
	}
	frame := make([]byte, 8+len(compressed))
	copy(frame[:4], segmentMagic)
	binary.BigEndian.PutUint32(frame[4:8], uint32(len(compressed)))
	copy(frame[8:], compressed)
	n, err := writer.file.Write(frame)
	writer.size += int64(n)
	return err
}

func (d *database) rotate(writer *segmentWriter) error {
	if writer.file != nil {
		if err := errors.Join(writer.file.Sync(), writer.file.Close()); err != nil {
			return err
		}
	}
	d.sequence++
	created := time.Now().UnixNano()
	kind := writer.kind
	if kind == "" {
		if writer == &d.detail {
			kind = "detail"
		} else {
			kind = "aggregate"
		}
	}
	path := filepath.Join(d.dir, kind+"-"+strconv.FormatInt(created, 10)+"-"+strconv.FormatUint(d.sequence, 10)+".sbh")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	*writer = segmentWriter{kind: kind, file: file, path: path, created: created}
	return nil
}

func (d *database) Prune(cutoff time.Time) error {
	d.access.Lock()
	defer d.access.Unlock()
	d.pruneCutoff.Store(cutoff.UnixNano())
	now := time.Now()
	files, err := d.segmentFilesLocked()
	if err != nil {
		return err
	}
	for _, file := range files {
		retention := d.aggregateRetention
		if file.kind == "detail" {
			retention = d.detailRetention
		}
		if now.Sub(time.Unix(0, file.created)) > retention && !d.isActivePath(file.path) {
			_ = os.Remove(file.path)
		}
	}
	return d.enforceLimitLocked()
}

type segmentFile struct {
	path    string
	kind    string
	created int64
	size    int64
}

func (d *database) segmentFilesLocked() ([]segmentFile, error) {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return nil, err
	}
	files := make([]segmentFile, 0, len(entries))
	for _, entry := range entries {
		parts := strings.Split(entry.Name(), "-")
		if len(parts) < 3 || (parts[0] != "detail" && parts[0] != "aggregate") {
			continue
		}
		created, parseErr := strconv.ParseInt(parts[1], 10, 64)
		if parseErr != nil {
			continue
		}
		info, statErr := entry.Info()
		if statErr != nil {
			continue
		}
		files = append(files, segmentFile{filepath.Join(d.dir, entry.Name()), parts[0], created, info.Size()})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].created < files[j].created })
	return files, nil
}

func (d *database) isActivePath(path string) bool {
	return path == d.detail.path || path == d.aggregate.path
}

func (d *database) enforceLimitLocked() error {
	files, err := d.segmentFilesLocked()
	if err != nil {
		return err
	}
	var total int64
	for _, file := range files {
		total += file.size
	}
	for _, kind := range []string{"detail", "aggregate"} {
		for _, file := range files {
			if total <= d.maxDiskSize {
				return nil
			}
			if file.kind != kind || d.isActivePath(file.path) {
				continue
			}
			if err = os.Remove(file.path); err == nil {
				total -= file.size
			}
		}
	}
	return nil
}

func (d *database) readBlocks(kind string, reverse bool, callback func(segmentBlock) bool) error {
	// Queries only read immutable segment files.  Keep the read lock while the
	// frame is decoded so rotation/pruning cannot unlink a file underneath us,
	// while allowing concurrent dashboard queries without serializing zstd work.
	d.access.RLock()
	defer d.access.RUnlock()
	files, err := d.segmentFilesLocked()
	if err != nil {
		return err
	}
	if reverse {
		sort.Slice(files, func(i, j int) bool { return files[i].created > files[j].created })
	}
	for _, file := range files {
		if file.kind != kind {
			continue
		}
		segment, readErr := os.Open(file.path)
		if readErr != nil {
			return readErr
		}
		frames, scanErr := scanSegmentFrames(segment)
		if scanErr != nil {
			segment.Close()
			return fmt.Errorf("scan history segment %s: %w", filepath.Base(file.path), scanErr)
		}
		var compressed []byte
		var plain []byte
		readFrame := func(frame segmentFrame) (bool, error) {
			if cap(compressed) < int(frame.length) {
				compressed = make([]byte, frame.length)
			} else {
				compressed = compressed[:frame.length]
			}
			if _, frameErr := segment.ReadAt(compressed, frame.offset); frameErr != nil {
				return false, frameErr
			}
			decoded, decodeErr := d.decoder.DecodeAll(compressed, plain[:0])
			if decodeErr != nil {
				return false, decodeErr
			}
			plain = decoded
			var block segmentBlock
			if jsonErr := json.Unmarshal(plain, &block); jsonErr != nil {
				return false, jsonErr
			}
			return callback(block), nil
		}
		if reverse {
			for index := len(frames) - 1; index >= 0; index-- {
				keepGoing, frameErr := readFrame(frames[index])
				if frameErr != nil {
					segment.Close()
					return frameErr
				}
				if !keepGoing {
					segment.Close()
					return nil
				}
			}
		} else {
			for _, frame := range frames {
				keepGoing, frameErr := readFrame(frame)
				if frameErr != nil {
					segment.Close()
					return frameErr
				}
				if !keepGoing {
					segment.Close()
					return nil
				}
			}
		}
		if closeErr := segment.Close(); closeErr != nil {
			return closeErr
		}
	}
	return nil
}

type segmentFrame struct {
	offset int64
	length uint32
}

// scanSegmentFrames reads only 8-byte headers. It intentionally tolerates a
// short final header/body left by a crash, while rejecting corrupt interior
// frames and unreasonable allocation requests.
func scanSegmentFrames(segment *os.File) ([]segmentFrame, error) {
	info, err := segment.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	frames := make([]segmentFrame, 0, max(1, int(size/(64<<10))))
	var header [8]byte
	for offset := int64(0); offset+8 <= size; {
		if _, err = segment.ReadAt(header[:], offset); err != nil {
			return nil, err
		}
		if string(header[:4]) != segmentMagic {
			return nil, errors.New("invalid frame magic")
		}
		length := binary.BigEndian.Uint32(header[4:])
		if length == 0 || length > maxHistoryFrameSize {
			return nil, fmt.Errorf("invalid frame size %d", length)
		}
		bodyOffset := offset + 8
		if bodyOffset+int64(length) > size {
			break
		}
		frames = append(frames, segmentFrame{offset: bodyOffset, length: length})
		offset = bodyOffset + int64(length)
	}
	return frames, nil
}

func (d *database) Connections(query Query) (ConnectionPage, error) {
	query = normalizeQuery(query)
	if cutoff := d.pruneCutoff.Load(); cutoff > 0 && query.Start.Before(time.Unix(0, cutoff)) {
		query.Start = time.Unix(0, cutoff)
	}
	var page ConnectionPage
	err := d.readBlocks("detail", true, func(block segmentBlock) bool {
		for index := len(block.Records) - 1; index >= 0; index-- {
			record := block.Records[index]
			if record.ClosedAt.After(query.End) || record.ClosedAt.Before(query.Start) || !recordMatches(record, query.Search) {
				continue
			}
			if page.Total >= query.Offset && len(page.Data) < query.Limit {
				page.Data = append(page.Data, record)
			}
			page.Total++
		}
		return true
	})
	return page, err
}

func (d *database) scanAggregates(query Query, callback func(aggregate)) error {
	query = normalizeQuery(query)
	if cutoff := d.pruneCutoff.Load(); cutoff > 0 && query.Start.Before(time.Unix(0, cutoff)) {
		query.Start = time.Unix(0, cutoff)
	}
	useHours := query.End.Sub(query.Start) > 48*time.Hour
	return d.readBlocks("aggregate", false, func(block segmentBlock) bool {
		for _, item := range block.Aggregates {
			itemTime := time.Unix(item.Bucket, 0)
			if item.Hour != useHours || itemTime.Before(query.Start) || itemTime.After(query.End) {
				continue
			}
			callback(item)
		}
		return true
	})
}

func (d *database) Summary(query Query) (Summary, error) {
	var summary Summary
	err := d.scanAggregates(query, func(item aggregate) {
		summary.Upload += item.Upload
		summary.Download += item.Download
		summary.Connections += item.Connections
	})
	return summary, err
}

func (d *database) Trend(query Query) ([]TrafficPoint, error) {
	points := make(map[int64]*TrafficPoint)
	err := d.scanAggregates(query, func(item aggregate) {
		point := points[item.Bucket]
		if point == nil {
			point = &TrafficPoint{Time: time.Unix(item.Bucket, 0).UTC()}
			points[item.Bucket] = point
		}
		point.Upload += item.Upload
		point.Download += item.Download
		point.Connections += item.Connections
	})
	result := make([]TrafficPoint, 0, len(points))
	for _, point := range points {
		result = append(result, *point)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Time.Before(result[j].Time) })
	return result, err
}

func (d *database) Dimensions(name string, query Query) (DimensionPage, error) {
	query = normalizeQuery(query)
	values := make(map[string]*Dimension)
	err := d.scanAggregates(query, func(item aggregate) {
		value := aggregateDimension(item, name)
		if value == "" || query.Search != "" && !strings.Contains(strings.ToLower(value), strings.ToLower(query.Search)) {
			return
		}
		dimension := values[value]
		if dimension == nil {
			dimension = &Dimension{Value: value}
			values[value] = dimension
		}
		dimension.Upload += item.Upload
		dimension.Download += item.Download
		dimension.Connections += item.Connections
	})
	all := make([]Dimension, 0, len(values))
	for _, value := range values {
		all = append(all, *value)
	}
	sort.Slice(all, func(i, j int) bool {
		left, right := all[i].Upload+all[i].Download, all[j].Upload+all[j].Download
		if left == right {
			return all[i].Value < all[j].Value
		}
		return left > right
	})
	page := DimensionPage{Total: len(all)}
	if query.Offset < len(all) {
		page.Data = all[query.Offset:min(query.Offset+query.Limit, len(all))]
	}
	return page, err
}

func normalizeQuery(query Query) Query {
	if query.End.IsZero() {
		query.End = time.Now()
	}
	if query.Start.IsZero() {
		query.Start = query.End.Add(-24 * time.Hour)
	}
	if query.Limit <= 0 {
		query.Limit = 100
	} else if query.Limit > 2000 {
		query.Limit = 2000
	}
	if query.Offset < 0 {
		query.Offset = 0
	}
	return query
}

func recordMatches(record Record, search string) bool {
	if search == "" {
		return true
	}
	search = strings.ToLower(search)
	return strings.Contains(strings.ToLower(record.Domain), search) || strings.Contains(strings.ToLower(record.DestinationIP), search) || strings.Contains(strings.ToLower(record.SourceIP), search) || strings.Contains(strings.ToLower(record.Outbound), search) || strings.Contains(strings.ToLower(record.Rule), search) || strings.Contains(strings.ToLower(record.Process), search)
}

func aggregateDimension(item aggregate, name string) string {
	switch name {
	case "domains":
		return item.Domain
	case "ips":
		return item.IP
	case "outbounds":
		return item.Outbound
	case "rules":
		return item.Rule
	case "sources":
		return item.Source
	default:
		return ""
	}
}

func mergeAggregate(target map[aggregateKey]aggregate, key aggregateKey, upload, download, connections int64) {
	item := target[key]
	item.Hour = key.Hour
	item.Bucket, item.Domain, item.IP = key.Bucket, key.Domain, key.IP
	item.Source, item.Outbound, item.Rule = key.Source, key.Outbound, key.Rule
	item.Upload += upload
	item.Download += download
	item.Connections += connections
	target[key] = item
}
