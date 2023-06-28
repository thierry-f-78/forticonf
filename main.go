package main

import "encoding/json"
import "flag"
import "fmt"
import "net"
import "os"
import "sort"
import "strconv"
import "strings"

type ProtoRules struct {
	Protocol string `json:"protocol"`
	Rules int `json:"rules"`
}

func main() {
	var file string
	var dest string
	var vdom string
	var err error
	var str string
	var src string
	var index *Index
	var ok bool
	var pols []*Policy
	var inter []*Policy
	var final []*Policy
	var ipnet *net.IPNet
	var intersection_started bool
	var data []byte
	var proto string
	var tcp_port string
	var udp_port string
	var used_pro bool
	var protocol_list []*ProtoRules
	var port int
	var src_mask int
	var search string
	var searchi string
	var vdomlist bool
	var rulesid string
	var rule int

	flag.StringVar(&file,     "config",     "",    "Expect config file")
	flag.StringVar(&vdom,     "vdom",       "",    "Perform requests in this vdom")
	flag.BoolVar(&vdomlist,   "vdom-list",  false, "List avalaible VDOM")
	flag.StringVar(&dest,     "dest",       "",    "Filter policies which allow access to this destination IP or network address. This argument can take more than one address using comma as separator.")
	flag.StringVar(&src,      "src",        "",    "Filter policies which allow access to this source IP or network address. This argument can take more than one address using comma as separator.")
	flag.IntVar(&src_mask,    "src-mask",   0,     "Filter policies which allow access to this source IP or network address. This argument can take more than one address using comma as separator.")
	flag.StringVar(&tcp_port, "tcp",        "",    "Filter policies which allow access to this TCP port. This argument can take more than one port using comma as separator. Note this implies proto TCP")
	flag.StringVar(&udp_port, "udp",        "",    "Filter policies which allow access to this TCP port. This argument can take more than one port using comma as separator. Note this implies proto UDP")
	flag.StringVar(&proto,    "proto",      "",    "Filter policies which allow access to this protocol. This argument can take more than one protocol using comma as separator.")
	flag.BoolVar(&used_pro,   "used-proto", false, "List all protocols in use in the vdom")
	flag.StringVar(&search,   "search",     "",    "List all policies containing the search string in name, comments, adresses or services")
	flag.StringVar(&searchi,  "searchi",    "",    "Same than search but case insensitive")
	flag.StringVar(&rulesid,  "rules-id",   "",    "Filter comma separated list of rules id")
	flag.Parse()

	if file == "" {
		fmt.Fprintf(os.Stderr, "Expect configuration file\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	err = read_conf(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	for str, _ = range Vdom_index {
		Vdom_list = append(Vdom_list, str)
		err = resolve_links(Vdom_index[str])
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
	}

	if vdomlist {

		/* Display data */
		data, err = json.MarshalIndent(Vdom_list, "", "    ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}

		/* End of commands */
		os.Exit(0)
	}

	if vdom != "" {
		index, ok = Vdom_index[vdom]
		if !ok {
			fmt.Fprintf(os.Stderr, "vdom %q doesn't exist. available vdom are: %s\n", vdom, strings.Join(Vdom_list, ", "))
			os.Exit(1)
		}
	}

	/* Check we have a vdom to search */
	if (used_pro || search != "" || searchi != "" || dest != "" || src != "" || tcp_port != "" || udp_port != "" || proto != "") && index == nil {
		fmt.Fprintf(os.Stderr, "must precise vdom with this request. available vdom are: %s\n", strings.Join(Vdom_list, ", "))
		os.Exit(1)
	}

	if used_pro {

		/* List protocols */
		for proto, pols = range index.Service_proto_index {
			protocol_list = append(protocol_list, &ProtoRules{
				Protocol: proto,
				Rules: len(pols),
			})
		}

		/* Display data */
		data, err = json.MarshalIndent(protocol_list, "", "    ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
		_, err = os.Stdout.Write(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}

		/* End of commands */
		os.Exit(0)
	}

	if dest != "" {

		inter = nil

		/* Split destination using ',' as separator */
		for _, dest = range strings.Split(dest, ",") {

			/* Decode IP */
			ipnet, err = ip2net(dest)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				os.Exit(1)
			}

			/* lookup policies */
			pols = list_policy_by_target(index, ipnet)

			/* Merge inter with pols */
			inter = merge_policies(pols, inter)
		}

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, inter, final)
	}

	if src != "" {

		inter = nil

		/* Split destination using ',' as separator */
		for _, src = range strings.Split(src, ",") {

			/* Decode IP string */
			ipnet, err = ip2net(src)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s\n", err.Error())
				os.Exit(1)
			}

			/* lookup policies */
			pols = list_policy_by_source(index, ipnet)

			/* Merge inter with pols */
			inter = merge_policies(pols, inter)
		}

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, inter, final)
	}

	if tcp_port != "" {

		inter = nil

		/* Split destination using ',' as separator */
		for _, src = range strings.Split(tcp_port, ",") {

			/* Decode IP string */
			port, err = strconv.Atoi(src)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Can't decode port %q: %s\n", src, err.Error())
				os.Exit(1)
			}

			/* lookup policies */
			pols = list_policy_by_tcp_port(index, port)

			/* Merge inter with pols */
			inter = merge_policies(pols, inter)
		}

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, inter, final)
	}

	if udp_port != "" {

		inter = nil

		/* Split destination using ',' as separator */
		for _, src = range strings.Split(tcp_port, ",") {

			/* Decode IP string */
			port, err = strconv.Atoi(src)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Can't decode port %q: %s\n", src, err.Error())
				os.Exit(1)
			}

			/* lookup policies */
			pols = list_policy_by_udp_port(index, port)

			/* Merge inter with pols */
			inter = merge_policies(pols, inter)
		}

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, inter, final)
	}

	if proto != "" {

		inter = nil

		/* Split destination using ',' as separator */
		for _, src = range strings.Split(proto, ",") {

			/* lookup policies */
			pols = list_policy_by_proto(index, src)

			/* Merge inter with pols */
			inter = merge_policies(pols, inter)
		}

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, inter, final)
	}

	if src_mask > 0 {

		/* lookup policies */
		pols = list_policy_by_source_mask(index, src_mask)

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, pols, final)
	}

	if search != "" {

		/* Perform search */
		pols = list_policy_by_search(index, false, search)

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, pols, final)
	}

	if searchi != "" {

		/* Perform search */
		pols = list_policy_by_search(index, true, searchi)

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, pols, final)
	}

	if rulesid != "" {

		inter = nil

		/* Split destination using ',' as separator */
		for _, src = range strings.Split(rulesid, ",") {

			/* Convert rule string to int */
			rule, err = strconv.Atoi(src)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Can't decode rule id %q: %s\n", src, err.Error())
				os.Exit(1)
			}

			/* lookup policies */
			pols = list_policy_by_rule(index, rule)

			/* Merge inter with pols */
			inter = merge_policies(pols, inter)
		}

		/* Merge inter with final. we keep intersection of rules */
		final = intersection_policies(&intersection_started, inter, final)
	}

	/* Sort final list by rule id */
	sort.Slice(final, func(i, j int)(bool) {
		return final[i].Id < final[j].Id
	})

	/* display final data */
	if final == nil {
		final = make([]*Policy, 0)
	}
	data, err = json.MarshalIndent(final, "", "    ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
	_, err = os.Stdout.Write(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}

func ip2net(network string)(*net.IPNet, error) {
	var ip net.IP
	var ipnet *net.IPNet
	var err error

	if !strings.Contains(network, "/") {
		ip = net.ParseIP(network)
		if ip == nil {
			return nil, fmt.Errorf("Cannot decode IP %q", network)
		}
		ipnet = &net.IPNet{
			IP: ip,
			Mask: net.CIDRMask(32, 32),
		}
	} else {
		_, ipnet, err = net.ParseCIDR(network)
		if err != nil {
			return nil, fmt.Errorf("Cannot decode IP %q: %s", network, err.Error())
		}
	}

	return ipnet, nil
}

func intersection_policies(intersection_started *bool, new_list []*Policy, final_list []*Policy)([]*Policy) {
	var out_list []*Policy
	var p1 *Policy
	var p2 *Policy

	if !*intersection_started {
		*intersection_started = true
		return new_list
	}

	for _, p1 = range new_list {
		for _, p2 = range final_list {
			if p1 == p2 {
				out_list = append(out_list, p1)
				break
			}
		}
	}

	return out_list
}

func merge_policies(new_list []*Policy, final_list []*Policy)([]*Policy) {
	var p1 *Policy
	var p2 *Policy

	merge_loop1: for _, p1 = range new_list {
		for _, p2 = range final_list {
			if p1 == p2 {
				continue merge_loop1
			}
		}
		final_list = append(final_list, p1)
	}
	return final_list
}
