package caddy_fail2ban

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/caddyserver/caddy/v2"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
)

type banQuery struct {
	response chan bool
	ip       string
}

type Banlist struct {
	ctx        caddy.Context
	bannedIps  []string
	shutdown   chan bool
	queries    chan banQuery
	logger     *zap.Logger
	banfile    *string
	reload     chan chan bool
	reloadSubs []chan bool
}

func NewBanlist(ctx caddy.Context, logger *zap.Logger, banfile *string) Banlist {
	banlist := Banlist{
		ctx:     ctx,
		queries: make(chan banQuery),
		logger:  logger,
		banfile: banfile,
		reload:  make(chan chan bool),
	}
	return banlist
}

func (b *Banlist) Start() {
	go b.monitorBannedIps()
}

func (b *Banlist) IsBanned(remote_ip string) bool {
	response := make(chan bool)
	query := banQuery{
		response,
		remote_ip,
	}
	b.queries <- query
	isBanned := <-response
	close(response)
	return isBanned
}

func (b *Banlist) Reload() {
	resp := make(chan bool)

	b.reload <- resp
	<-resp
}

func (b *Banlist) monitorBannedIps() {
	b.logger.Info("Starting monitor for banned IPs")
	defer func() {
		b.logger.Info("Shutting down monitor for banned IPs")
	}()

	// Load initial list
	err := b.loadBannedIps()
	if err != nil {
		b.logger.Error("Error loading initial list of banned IPs", zap.Error(err))
		return
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		b.logger.Error("Error creating monitor", zap.Error(err))
		return
	}
	defer watcher.Close()

	// Watch the directory that the banfile is in as sometimes files can be
	// written to by replacement (see https://pkg.go.dev/github.com/fsnotify/fsnotify#readme-watching-a-file-doesn-t-work-well)
	err = watcher.Add(filepath.Dir(*b.banfile))
	if err != nil {
		b.logger.Error("Error monitoring banfile", zap.Error(err), zap.String("banfile", *b.banfile))
	}

	for {
		select {
		case resp := <-b.reload:
			// Trigger reload of banned IPs
			err = b.loadBannedIps()
			if err != nil {
				b.logger.Error("Error when trying to explicitly reloading list of banned IPs", zap.Error(err))
				return
			}
			b.logger.Debug("Banlist reloaded")
			resp <- true
		case query := <-b.queries:
			// Respond to query whether an IP has been banned
			b.logger.Debug("Handling ban query", zap.String("remote_ip", query.ip))
			b.handleQuery(query)
		case err, ok := <-watcher.Errors:
			// Handle errors from fsnotify
			if !ok {
				b.logger.Error("Error channel closed unexpectedly, stopping monitor")
				return
			}
			b.logger.Error("Error from fsnotify", zap.Error(err))
		case event, ok := <-watcher.Events:
			// Respond to changed file events from fsnotify
			if !ok {
				b.logger.Error("Watcher closed unexpectedly, stopping monitor")
				return
			}
			// We get events for the whole directory but only want to do work if the
			// changed file is our banfile
			if (event.Has(fsnotify.Write) || event.Has(fsnotify.Create)) && event.Name == *b.banfile {
				b.logger.Debug("File has changed, reloading banned IPs")
				err = b.loadBannedIps()
				if err != nil {
					b.logger.Error("Error when trying to reload banned IPs because of inotify event", zap.Error(err))
					return
				}
			}
		case <-b.ctx.Done():
			// Caddy will close the context when it's time to shut down
			b.logger.Debug("Context finished, shutting down")
			return
		}
	}
}

func (b *Banlist) handleQuery(query banQuery) {
	remote_ip := query.ip
	for _, ip := range b.bannedIps {
		b.logger.Debug("Checking IP", zap.String("ip", ip), zap.String("remote_ip", remote_ip))
		if ip == remote_ip {
			query.response <- true
			return
		}
	}
	query.response <- false
}

// Provide a channel that will receive a boolean true value whenever the list
// of banned IPs has been reloaded. Mostly useful for tests so they can wait
// for the inotify event rather than sleep
func (b *Banlist) subscribeToReload(notify chan bool) {
	b.reloadSubs = append(b.reloadSubs, notify)
}

// loadBannedIps loads list of banned IPs from file on disk and notifies
// subscribers in case it was successful
func (b *Banlist) loadBannedIps() error {
	bannedIps, err := b.getBannedIps()
	if err != nil {
		b.logger.Error("Error getting list of banned IPs")
		return err
	} else {
		b.bannedIps = bannedIps
		for _, n := range b.reloadSubs {
			n <- true
		}
		// only respond once then clear subs, otherwise further attempts might
		// block as the receiver only reads one event rather than constantly
		// draining it.
		b.reloadSubs = nil
		return nil
	}
}

func (b *Banlist) getBannedIps() ([]string, error) {

	// Open banfile
	// Try to open file
	banfileHandle, err := os.Open(*b.banfile)
	if err != nil {
		b.logger.Info("Creating new file since Open failed", zap.String("banfile", *b.banfile), zap.Error(err))
		// Try to create new file, maybe the file didn't exist yet
		banfileHandle, err = os.Create(*b.banfile)
		if err != nil {
			b.logger.Error("Error creating banfile", zap.String("banfile", *b.banfile), zap.Error(err))
			return nil, fmt.Errorf("cannot open or create banfile: %v", err)
		}
	}
	defer banfileHandle.Close()

	// read banned IPs
	bannedIps := make([]string, 0)
	scanner := bufio.NewScanner(banfileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		b.logger.Debug("Adding banned IP to list", zap.String("banned_addr", line))
		bannedIps = append(bannedIps, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error parsing banfile: %v", err)
	}

	return bannedIps, nil
}
