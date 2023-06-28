package main

import "encoding/binary"
import "fmt"
import "io"
import "net"
import "strings"

import "github.com/thierry-f-78/go-radix"

type ServiceGroup struct {
	Name string `json:"name,omitempty"`
	member []string
	Member []*Service `json:"member,omitempty"`
}

type Service struct {
	Name string `json:"name,omitempty"`
	Comment string `json:"comment,omitempty"`
	Category string `json:"category,omitempty"`
	Tcp_portrange []interface{} `json:"tcp_portrange,omitempty"` /* interface{} = int or []int */
	Udp_portrange []interface{} `json:"udp_portrange,omitempty"` 
	Protocol string `json:"protocol,omitempty"`
	Protocol_number int `json:"protocol_number,omitempty"`
}

type Object struct {
	Name string `json:"name,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Comment string `json:"comment,omitempty"`
	Fqdn string `json:"fqdn,omitempty"`
	Network string `json:"network,omitempty"`
	Range_start string `json:"range_start,omitempty"`
	Range_end string `json:"range_end,omitempty"`
	Macaddr string `json:"macaddr,omitempty"`
}

type Vip struct {
	Name string `json:"name,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Comment string `json:"comment,omitempty"`
	Extip string `json:"extip,omitempty"`
	Mappedip string `json:"mappedip,omitempty"`
	Extintf string `json:"extintf,omitempty"`
	Portforward string `json:"portforward,omitempty"`
	Extport int `json:"extport,omitempty"`
	Mappedport int `json:"mappedport,omitempty"`
}

type Policy struct {
	Id int `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Comments string `json:"comments,omitempty"`
	Srcintf string `json:"srcintf,omitempty"`
	Dstintf string `json:"dstintf,omitempty"`
	Action string `json:"action,omitempty"`
	srcaddr []string /* original names in conf */
	Srcaddr []interface{} `json:"srcaddr,omitempty"`
	srcaddr_lookup []*Object /* contains pointer to objets */
	dstaddr []string /* original names in conf */
	Dstaddr []interface{} `json:"dstaddr,omitempty"`
	dstaddr_lookup []*Object /* contains pointer to objets */
	service []string
	service_lookup []*Service
	Service []interface{} `json:"service,omitempty"`
	Groups []string `json:"groups,omitempty"`
	Schedule string `json:"schedule,omitempty"`
	Logtraffic string `json:"logtraffic,omitempty"`
}

type Group struct {
	Name string `json:"name,omitempty"`
	Uuid string `json:"uuid,omitempty"`
	Comment string `json:"comment,omitempty"`
	member []string
	Member []interface{} `json:"member,omitempty"`
	member_lookup []*Object /* contains pointer to objets */
}

type Index struct {
	Vdom string `json:"vdom,omitempty"`
	Object_by_name map[string]*Object `json:"object_by_name,omitempty"`
	Group_by_name map[string]*Group `json:"group_by_name,omitempty"`
	Service_by_name map[string]*Service `json:"service_by_name,omitempty"`
	ServiceGroup_by_name map[string]*ServiceGroup `json:"servicegroup_by_name,omitempty"`
	Vip_by_name map[string]*Vip `json:"vip_by_name,omitempty"`
	Policy_list []*Policy `json:"policy_list,omitempty"`
	Policy_by_ruleid_index map[int]*Policy
	Target_tree *radix.Radix
	Target_mask_index map[int][]*Policy
	Source_tree *radix.Radix
	Source_mask_index map[int][]*Policy
	Object_tree *radix.Radix
	Service_name_index map[string][]*Policy
	Service_tcp_index map[int][]*Policy
	Service_udp_index map[int][]*Policy
	Service_proto_index map[string][]*Policy
}

var Vdom_list []string
var Vdom_index map[string]*Index = make(map[string]*Index)

func removeDuplicate[T *Service](sliceList []T)([]T) {
	var allKeys map[T]bool = make(map[T]bool)
	var out []T
	var item T
	var ok bool

	for _, item = range sliceList {
		_, ok = allKeys[item]
		if !ok {
			allKeys[item] = true
			out = append(out, item)
		}
	}
	return out
}

func appendNoDup[T *Policy|*Service|*Group|*Object|*ServiceGroup|string](sliceList []T, newItem T)([]T) {
	var item T

	for _, item = range sliceList {
		if item == newItem {
			return sliceList
		}
	}
	return append(sliceList, newItem)
}

func get_vdom(name string)(*Index) {
	var ok bool
	var index *Index

	index, ok = Vdom_index[name]
	if !ok {
		index = &Index{
			Vdom: name,
			Object_by_name: make(map[string]*Object),
			Group_by_name: make(map[string]*Group),
			Service_by_name: make(map[string]*Service),
			ServiceGroup_by_name: make(map[string]*ServiceGroup),
			Vip_by_name: make(map[string]*Vip),
			Policy_list: nil,
			Policy_by_ruleid_index: make(map[int]*Policy),
			Target_tree: radix.NewRadix(),
			Target_mask_index: make(map[int][]*Policy),
			Source_tree: radix.NewRadix(),
			Source_mask_index: make(map[int][]*Policy),
			Object_tree: radix.NewRadix(),
			Service_name_index: make(map[string][]*Policy),
			Service_tcp_index: make(map[int][]*Policy),
			Service_udp_index: make(map[int][]*Policy),
			Service_proto_index: make(map[string][]*Policy),
		}
		Vdom_index[name] = index
	}
	return index
}

func lookup_service(index *Index, name string)([]*Service) {
	var ok bool
	var s *Service
	var sg *ServiceGroup

	s, ok = index.Service_by_name[name]
	if ok {
		return []*Service{s}
	}
	sg, ok = index.ServiceGroup_by_name[name]
	if ok {
		return sg.Member
	}
	return nil
}

func lookup_service_real(index *Index, name string)(interface{}) {
	var ok bool
	var s *Service
	var sg *ServiceGroup

	s, ok = index.Service_by_name[name]
	if ok {
		return s
	}
	sg, ok = index.ServiceGroup_by_name[name]
	if ok {
		return sg
	}
	return nil
}

func lookup_object(index *Index, name string)([]*Object) {
	var ok bool
	var o *Object
	var g *Group

	o, ok = index.Object_by_name[name]
	if ok {
		return []*Object{o}
	}
	g, ok = index.Group_by_name[name]
	if ok {
		return g.member_lookup
	}
	return nil
}

func lookup_real(index *Index, name string)(interface{}) {
	var ok bool
	var o *Object
	var g *Group
	var v *Vip

	o, ok = index.Object_by_name[name]
	if ok {
		return o
	}
	g, ok = index.Group_by_name[name]
	if ok {
		return g
	}
	v, ok = index.Vip_by_name[name]
	if ok {
		return v
	}
	return nil
}

func read_conf(file string)(error) {
	var s *Stream
	var err error
	var fg *FG
	var kw string

	/* create new stream */
	s, err = StreamNew(file)
	if err != nil {
		return fmt.Errorf("%s", err.Error())
	}
	defer s.Close()

	/* new grammar parser */
	fg = &FG{s: s}

	/* Start grammar parser */
	err = fg.ConfigList(true)
	if err != nil {
		return fmt.Errorf("%s", err.Error())
	}

	/* Expect end of file */
	kw, err = fg.s.Next()
	if err == nil {
		return fmt.Errorf("Expect end of file, got %q", kw)
	}
	if err != io.EOF {
		return fmt.Errorf("Expect end of file, got %s", err.Error())
	}
	return nil
}

func index_network_cidr(tree *radix.Radix, ipnet *net.IPNet, i interface{}) {
	var node *radix.Node

	node = tree.IPv4Get(ipnet)
	if node != nil {
		node.Data = append(node.Data.([]interface{}), i)
	} else {
		tree.IPv4Insert(ipnet, []interface{}{i})
	}
}

func index_cidr(tree *radix.Radix, network string, i interface{})(*net.IPNet, error) {
	var ipnet *net.IPNet
	var err error

	_, ipnet, err = net.ParseCIDR(network)
	if err != nil {
		return nil, err
	}
	index_network_cidr(tree, ipnet, i)
	return ipnet, nil
}

func index_range(tree *radix.Radix, ip_start_str string, ip_end_str string, i interface{})(error) {
	var ip net.IP
	var ip_end net.IP
	var browse_ip uint32
	var end_ip uint32
	var ipnet *net.IPNet

	ip = net.ParseIP(ip_start_str)
	if ip == nil {
		return fmt.Errorf("cannot decode ip %q", ip_start_str)
	}
	ip = ip.To4()
	if ip == nil {
		return fmt.Errorf("ip %q is not IPv4", ip_start_str)
	}

	ip_end = net.ParseIP(ip_end_str)
	if ip_end == nil {
		return fmt.Errorf("cannot decode ip %q", ip_end_str)
	}
	ip_end = ip_end.To4()
	if ip_end == nil {
		return fmt.Errorf("ip %q is not IPv4", ip_end_str)
	}

	/* browse list of all ip in the range */
	browse_ip = binary.BigEndian.Uint32([]byte(ip))
	end_ip = binary.BigEndian.Uint32([]byte(ip_end))
	for browse_ip = browse_ip; browse_ip <= end_ip; browse_ip++ {
		binary.BigEndian.PutUint32(ip, browse_ip)
		ipnet = &net.IPNet{
			IP: ip,
			Mask: net.CIDRMask(32, 32),
		}
		index_network_cidr(tree, ipnet, i)
	}

	return nil
}

func resolve_links(index *Index)(error) {
	var ok bool
	var g *Group
	var g2 *Group
	var o *Object
	var objects []*Object
	var p *Policy
	var ss []*Service
	var s *Service
	var sg *ServiceGroup
	var in_members []string
	var out_members []string
	var name string
	var err error
	var i interface{}
	var port int
	var prange []int
	var msz int
	var ipnet *net.IPNet

	/* Expand group including groups. check if object reference is group.
	 * If the object is group, group member are added in a queue and checked
	 * one by one. If one of the new nale is a group, is expanded in the queue,
	 * ... Warning : we do not check recursivity, with bad conf, this can
	 * create infinite loop
	 */
	for _, g = range index.Group_by_name {

		/* init queue with all members of current group */
		out_members = nil
		in_members = nil
		in_members = append(in_members, g.member...)

		for {

			/* input queue is empty, end of processing */
			if len(in_members) == 0 {
				break
			}

			/* pop first entry from queue */
			name = in_members[0]
			in_members = in_members[1:]

			/* Lookup name in group, if found, append all member of this new group to expand list */
			g2, ok = index.Group_by_name[name]
			if ok {
				in_members = append(in_members, g2.member...)
				continue
			}

			/* Just append the processed name to out_members */
			out_members = appendNoDup(out_members, name)
		}

		/* Resolve all members as objects */
		for _, name = range out_members {
			o, ok = index.Object_by_name[name]
			if !ok {
				return fmt.Errorf("Cannot lookup object %q used in group %q in vdom %q", name, g.Name, index.Vdom)
			}
			g.member_lookup = appendNoDup(g.member_lookup, o)
		}

		/* Resolve all display references */
		for _, name = range g.member {
			i = lookup_real(index, name)
			g.Member = append(g.Member, i)
		}
	}

	/* Resolve service group */
	for _, sg = range index.ServiceGroup_by_name {
		for _, name = range sg.member {
			s, ok = index.Service_by_name[name]
			if !ok {
				return fmt.Errorf("Cannot lookup service %q used in service group %q in vdom %q", name, sg.Name, index.Vdom)
			}
			sg.Member = appendNoDup(sg.Member, s)
		}
	}

	/* Resolve policy references */
	for _, p = range index.Policy_list {
		for _, name = range p.srcaddr {
			/* source address to list of objects */
			objects = lookup_object(index, name)
			if objects == nil {
				return fmt.Errorf("Cannot lookup object %q in policy %d", name, p.Id)
			}
			p.srcaddr_lookup = append(p.srcaddr_lookup, objects...)
			/* source adress to object or group */
			i = lookup_real(index, name)
			if i == nil {
				return fmt.Errorf("Cannot lookup object %q in policy %d", name, p.Id)
			}
			p.Srcaddr = append(p.Srcaddr, i)
		}
		for _, name = range p.dstaddr {
			/* destination address to list of objects */
			objects = lookup_object(index, name)
			if objects == nil {
				return fmt.Errorf("Cannot lookup object %q in policy %d", name, p.Id)
			}
			p.dstaddr_lookup = append(p.dstaddr_lookup, objects...)
			/* destination adress to object or group */
			i = lookup_real(index, name)
			if i == nil {
				return fmt.Errorf("Cannot lookup object %q in policy %d", name, p.Id)
			}
			p.Dstaddr = append(p.Dstaddr, i)
		}
		for _, name = range p.service {
			/* service name to expanded list of service */
			ss = lookup_service(index, name)
			if ss == nil {
				return fmt.Errorf("Cannot lookup object %q", name)
			}
			p.service_lookup = append(p.service_lookup, ss...)
			/* service name to service or service group */
			i = lookup_service_real(index, name)
			if i == nil {
				return fmt.Errorf("Cannot lookup object %q", name)
			}
			p.Service = append(p.Service, i)
		}

		/* Remove duplicates */
		p.service_lookup = removeDuplicate(p.service_lookup)
	}

	/* index policy by destination network, by source network and by service */
	for _, p = range index.Policy_list {

		/* Index by rule */
		index.Policy_by_ruleid_index[p.Id] = p

		for _, o = range p.srcaddr_lookup {
			if o.Network != "" {
				ipnet, err = index_cidr(index.Source_tree, o.Network, p)
				if err != nil {
					return fmt.Errorf("Error indexing CIDR %q for object %q in vdom %q: %s", o.Network, o.Name, index.Vdom, err.Error())
				}
				msz, _ = ipnet.Mask.Size()
				index.Source_mask_index[msz] = appendNoDup(index.Source_mask_index[msz], p)
			}
			if o.Range_start != "" && o.Range_end != "" {
				err = index_range(index.Source_tree, o.Range_start, o.Range_end, p)
				if err != nil {
					return fmt.Errorf("Error indexing ip-range object %q in vdom %q: %s", o.Name, index.Vdom, err.Error())
				}
			}
		}
		for _, o = range p.dstaddr_lookup {
			if o.Network != "" {
				ipnet, err = index_cidr(index.Target_tree, o.Network, p)
				if err != nil {
					return fmt.Errorf("Error indexing CIDR %q for object %q in vdom %q: %s", o.Network, o.Name, index.Vdom, err.Error())
				}
				msz, _ = ipnet.Mask.Size()
				index.Target_mask_index[msz] = appendNoDup(index.Target_mask_index[msz], p)
			}
			if o.Range_start != "" && o.Range_end != "" {
				err = index_range(index.Target_tree, o.Range_start, o.Range_end, p)
				if err != nil {
					return fmt.Errorf("Error indexing ip-range object %q in vdom %q: %s", o.Name, index.Vdom, err.Error())
				}
			}
		}
		for _, s = range p.service_lookup {
			index.Service_name_index[s.Name] = appendNoDup(index.Service_name_index[s.Name], p)
			p.service_lookup = removeDuplicate(p.service_lookup)
			index.Service_proto_index[s.Protocol] = appendNoDup(index.Service_proto_index[s.Protocol], p)
			for _, i = range s.Tcp_portrange {
				port, ok = i.(int)
				if ok {
					index.Service_tcp_index[port] = appendNoDup(index.Service_tcp_index[port], p)
				} else {
					prange, ok = i.([]int)
					if !ok {
						panic(fmt.Sprintf("expected value on interface{} are only 'int' or '[]int', got %T", i))
					}
					for port = prange[0]; port <= prange[1]; port++ {
						index.Service_tcp_index[port] = appendNoDup(index.Service_tcp_index[port], p)
					}
				}
			}
			for _, i = range s.Udp_portrange {
				port, ok = i.(int)
				if ok {
					index.Service_udp_index[port] = appendNoDup(index.Service_udp_index[port], p)
				} else {
					prange, ok = i.([]int)
					if !ok {
						panic(fmt.Sprintf("expected value on interface{} are only 'int' or '[]int', got %T", i))
					}
					for port = prange[0]; port <= prange[1]; port++ {
						index.Service_udp_index[port] = appendNoDup(index.Service_udp_index[port], p)
					}
				}
			}
		}
	}

	/* index objects by IP */
	for _, o = range index.Object_by_name {
		if o.Network != "" {
			_, err = index_cidr(index.Object_tree, o.Network, o)
			if err != nil {
				return fmt.Errorf("Error indexing CIDR %q for object %q in vdom %q: %s", o.Network, o.Name, index.Vdom, err.Error())
			}
		}
		if o.Range_start != "" && o.Range_end != "" {
			err = index_range(index.Object_tree, o.Range_start, o.Range_end, o)
			if err != nil {
				return fmt.Errorf("Error indexing ip-range object %q in vdom %q: %s", o.Name, index.Vdom, err.Error())
			}
		}
	}

	return nil
}

func list_policy_by_target(index *Index, ipnet *net.IPNet)([]*Policy) {
	var nodes []*radix.Node
	var node *radix.Node
	var i interface{}
	var is []interface{}
	var pols []*Policy
	var it *radix.Iter

	/* Lookup contains network */
	nodes = index.Target_tree.IPv4LookupLonguestPath(ipnet)
	for _, node = range nodes {
		is = node.Data.([]interface{})
		for _, i = range is {
			pols = append(pols, i.(*Policy))
		}
	}

	/* Lookup network contains */
	it = index.Target_tree.IPv4NewIter(ipnet)
	for it.Next() {
		node = it.Get()
		is = node.Data.([]interface{})
		for _, i = range is {
			pols = appendNoDup(pols, i.(*Policy))
		}
	}
	return pols
}

func list_policy_by_source(index *Index, ipnet *net.IPNet)([]*Policy) {
	var nodes []*radix.Node
	var node *radix.Node
	var i interface{}
	var is []interface{}
	var pols []*Policy
	var it *radix.Iter

	/* Lookup contains network */
	nodes = index.Source_tree.IPv4LookupLonguestPath(ipnet)
	for _, node = range nodes {
		is = node.Data.([]interface{})
		for _, i = range is {
			pols = append(pols, i.(*Policy))
		}
	}

	/* Lookup network contains */
	it = index.Source_tree.IPv4NewIter(ipnet)
	for it.Next() {
		node = it.Get()
		is = node.Data.([]interface{})
		for _, i = range is {
			pols = appendNoDup(pols, i.(*Policy))
		}
	}
	return pols
}

func list_policy_by_tcp_port(index *Index, port int)([]*Policy) {
	var pols []*Policy
	pols, _ = index.Service_tcp_index[port]
	return pols
}

func list_policy_by_udp_port(index *Index, port int)([]*Policy) {
	var pols []*Policy
	pols, _ = index.Service_udp_index[port]
	return pols
}

func list_policy_by_proto(index *Index, proto string)([]*Policy) {
	var pols []*Policy
	pols, _ = index.Service_proto_index[proto]
	return pols
}

func list_policy_by_source_mask(index *Index, mask_sz int)([]*Policy) {
	var pols []*Policy
	pols, _ = index.Source_mask_index[mask_sz]
	return pols
}

func list_policy_by_search(index *Index, case_insensitive bool, word string)([]*Policy) {
	var pols []*Policy
	var p *Policy
	var s string
	var i interface{}

	if case_insensitive {
		s = strings.ToLower(word)
	} else {
		s = word
	}

	browse_policies: for _, p = range index.Policy_list {
		if case_insensitive {
			if strings.Contains(strings.ToLower(p.Name), s) {
				pols = append(pols, p)
				continue
			}
			if strings.Contains(strings.ToLower(p.Comments), s) {
				pols = append(pols, p)
				continue
			}
		} else {
			if strings.Contains(p.Name, s) {
				pols = append(pols, p)
				continue
			}
			if strings.Contains(p.Comments, s) {
				pols = append(pols, p)
				continue
			}
		}
		for _, i = range p.Srcaddr {
			switch o := i.(type) {
			case *Object:
				if search_object(o, case_insensitive, s) {
					pols = append(pols, p)
					continue browse_policies
				}
			case *Group:
				if search_object_group(o, case_insensitive, s) {
					pols = append(pols, p)
					continue browse_policies
				}
			}
		}
		for _, i = range p.Dstaddr {
			switch o := i.(type) {
			case *Object:
				if search_object(o, case_insensitive, s) {
					pols = append(pols, p)
					continue browse_policies
				}
			case *Group:
				if search_object_group(o, case_insensitive, s) {
					pols = append(pols, p)
					continue browse_policies
				}
			}
		}
		for _, i = range p.Service {
			switch o := i.(type) {
			case *Service:
				if search_service(o, case_insensitive, s) {
					pols = append(pols, p)
					continue browse_policies
				}
			case *ServiceGroup:
				if search_service_group(o, case_insensitive, s) {
					pols = append(pols, p)
					continue browse_policies
				}
			}
		}
	}

	return pols
}

func search_object(o *Object, case_insensitive bool, s string)(bool) {
	if case_insensitive {
		if strings.Contains(strings.ToLower(o.Name), s) {
			return true
		}
		if strings.Contains(strings.ToLower(o.Comment), s) {
			return true
		}
		if strings.Contains(strings.ToLower(o.Fqdn), s) {
			return true
		}
		if strings.Contains(strings.ToLower(o.Macaddr), s) {
			return true
		}
	} else {
		if strings.Contains(o.Name, s) {
			return true
		}
		if strings.Contains(o.Comment, s) {
			return true
		}
		if strings.Contains(o.Fqdn, s) {
			return true
		}
		if strings.Contains(o.Macaddr, s) {
			return true
		}
	}
	return false
}

func search_object_group(og *Group, case_insensitive bool, s string)(bool) {
	var i interface{}

	if case_insensitive {
		if strings.Contains(strings.ToLower(og.Name), s) {
			return true
		}
		if strings.Contains(strings.ToLower(og.Comment), s) {
			return true
		}
	} else {
		if strings.Contains(og.Name, s) {
			return true
		}
		if strings.Contains(og.Comment, s) {
			return true
		}
	}

	for _, i = range og.Member {
		switch o := i.(type) {
		case *Object:
			if search_object(o, case_insensitive, s) {
				return true
			}
		case *Group:
			if search_object_group(o, case_insensitive, s) {
				return true
			}
		}
	}
	return false
}

func search_service(o *Service, case_insensitive bool, s string)(bool) {
	if case_insensitive {
		if strings.Contains(strings.ToLower(o.Name), s) {
			return true
		}
		if strings.Contains(strings.ToLower(o.Comment), s) {
			return true
		}
		if strings.Contains(strings.ToLower(o.Category), s) {
			return true
		}
	} else {
		if strings.Contains(o.Name, s) {
			return true
		}
		if strings.Contains(o.Comment, s) {
			return true
		}
		if strings.Contains(o.Category, s) {
			return true
		}
	}
	return false
}

func search_service_group(sg *ServiceGroup, case_insensitive bool, s string)(bool) {
	var i interface{}

	if case_insensitive {
		if strings.Contains(strings.ToLower(sg.Name), s) {
			return true
		}
	} else {
		if strings.Contains(sg.Name, s) {
			return true
		}
	}

	for _, i = range sg.Member {
		switch o := i.(type) {
		case *Service:
			if search_service(o, case_insensitive, s) {
				return true
			}
		case *ServiceGroup:
			if search_service_group(o, case_insensitive, s) {
				return true
			}
		}
	}
	return false
}

func list_policy_by_rule(index *Index, rule int)([]*Policy) {
	var p *Policy
	var ok bool

	p, ok = index.Policy_by_ruleid_index[rule]
	if !ok {
		return nil
	}
	return []*Policy{p}
}
