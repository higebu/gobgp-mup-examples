package main

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"time"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"
)

func main() {
	ctx := context.Background()
	s := server.NewBgpServer()
	go s.Serve()
	s.StartBgp(ctx, &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        65000,
			RouterId:   "10.10.10.10",
			ListenPort: -1,
		},
	})
	defer s.StopBgp(ctx, &api.StopBgpRequest{})

	// Generate Type 2 ST Route
	// https://www.ietf.org/archive/id/draft-mpmz-bess-mup-safi-03.html#name-generation-of-the-type-2-st
	rt, err := bgp.ParseRouteTarget("65000:100")
	if err != nil {
		log.Fatal(err)
	}
	mup := bgp.NewMUPExtended(100, 12345)
	ext := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt, mup})
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		ext,
		bgp.NewPathAttributeNextHop("10.10.10.10"),
	}
	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	addr := netip.MustParseAddr("10.0.0.1")
	teid := netip.MustParseAddr("0.0.48.57")
	nlri := bgp.NewMUPType2SessionTransformedRoute(rd, 64, addr, teid)
	path, err := apiutil.NewPath(nlri, false, attrs, time.Now())
	if err != nil {
		log.Fatal(err)
	}
	_, err = s.AddPath(ctx, &api.AddPathRequest{
		TableType: api.TableType_GLOBAL,
		Path:      path,
	})
	if err != nil {
		log.Fatal(err)
	}

	s.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_MUP}}, func(d *api.Destination) {
		fmt.Printf("Prefix: %s\n", d.Prefix)
		for _, p := range d.Paths {
			pa, err := apiutil.UnmarshalPathAttributes(p.Pattrs)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("PathAttributes: %s\n", pa)
		}
	})
}
