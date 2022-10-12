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

	// Generate Direct Segment Discovery route
	// https://www.ietf.org/archive/id/draft-mpmz-bess-mup-safi-01.html#name-generation-of-the-direct-se
	psid := &bgp.PathAttributePrefixSID{
		TLVs: []bgp.PrefixSIDTLVInterface{
			&bgp.SRv6L3ServiceAttribute{
				SubTLVs: []bgp.PrefixSIDTLVInterface{
					&bgp.SRv6InformationSubTLV{
						SID:              netip.MustParseAddr("2001:db8::").AsSlice(),
						Flags:            0,
						EndpointBehavior: uint16(bgp.ENDM_GTP4E),
						SubSubTLVs: []bgp.PrefixSIDTLVInterface{
							&bgp.SRv6SIDStructureSubSubTLV{
								LocalBlockLength:    32,
								LocatorNodeLength:   16,
								FunctionLength:      0,
								ArgumentLength:      0,
								TranspositionLength: 0,
								TranspositionOffset: 0,
							},
						},
					},
				},
			},
		},
	}
	rt, err := bgp.ParseRouteTarget("65000:100")
	if err != nil {
		log.Fatal(err)
	}
	mup := bgp.NewMUPExtended(100, 12345)
	ext := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{rt, mup})
	attrs := []bgp.PathAttributeInterface{
		bgp.NewPathAttributeOrigin(0),
		ext,
		bgp.NewPathAttributeNextHop("a::1"),
		psid,
	}
	rd, _ := bgp.ParseRouteDistinguisher("100:100")
	addr := netip.MustParseAddr("a::1")
	nlri := bgp.NewMUPDirectSegmentDiscoveryRoute(rd, addr)
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

	s.ListPath(ctx, &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_MUP}}, func(d *api.Destination) {
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
