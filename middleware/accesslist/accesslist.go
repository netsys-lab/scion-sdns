package accesslist

import (
	"context"
	"net"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/yl2chen/cidranger"
)

// AccessList type
type AccessList struct {
	ranger cidranger.Ranger
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return accesslist
func New(cfg *config.Config) *AccessList {
	if len(cfg.AccessList) == 0 {
		cfg.AccessList = append(cfg.AccessList, "0.0.0.0/0")
		cfg.AccessList = append(cfg.AccessList, "::0/0")
	}

	a := new(AccessList)
	a.ranger = cidranger.NewPCTrieRanger()
	for _, cidr := range cfg.AccessList {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Error("Access list parse cidr failed", "error", err.Error())
			continue
		}

		err = a.ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))
		if err != nil {
			log.Error("Access list insert failed", "error", err.Error())
		}
	}

	return a
}

// Name return middleware name
func (a *AccessList) Name() string { return name }

// ServeDNS implements the Handle interface.
func (a *AccessList) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if ch.Writer.Internal() {
		ch.Next(ctx)
		return
	}

	remote := ch.Writer.RemoteIP()
	allowed, _ := a.ranger.Contains(remote)

	if !allowed {
		proto := ch.Writer.Proto()
		if remote != nil && proto != "scion" {
			//no reply to client
			log.Debug("AccessList DENIED", "remote", ch.Writer.RemoteIP(), "proto", ch.Writer.Proto())
			ch.Cancel()
			return
		} else {
			log.Debug("AccessList", "exemption for proto", proto)
		}
	}

	ch.Next(ctx)
}

const name = "accesslist"
