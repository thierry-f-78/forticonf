package main

import "fmt"
import "io"
import "net"
import "strconv"
import "strings"

var ignore = fmt.Errorf("ignore")

type FG struct {
	s *Stream
	current_vdom string
}

/* check keyword length */
func kwsl(kws []string, l int, line int)(error) {
	if len(kws) < l {
		return fmt.Errorf("keyword %q expect more keyword at line %d", strings.Join(kws, " "), line)
	}
	return nil
}

/* Eat all edit  section */
func (fg *FG)EditNext()(error) {
	var kws []string
	var err error

	for {
		kws, _, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "edit":
			err = fg.EditNext()
			if err != nil {
				return err
			}
		case "config":
			err = fg.ConfigEnd()
			if err != nil {
				return err
			}
		case "next":
			return nil
		}
	}
}

/* used to jump sections read all token until "end" */
func (fg *FG)ConfigEnd()(error) {
	var kws []string
	var err error

	for {
		kws, _, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "edit":
			err = fg.EditNext()
			if err != nil {
				return err
			}
		case "config":
			err = fg.ConfigEnd()
			if err != nil {
				return err
			}
		case "end":
			return nil
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallVip(v *Vip)(error) {
	var kws []string
	var err error
	var line int

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "set":
			err = kwsl(kws, 2, line); if err != nil { return err }
			switch kws[1] {
			case "uuid":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Uuid = kws[2]
			case "comment":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Comment = kws[2]
			case "extip":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Extip = kws[2]
			case "mappedip":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Mappedip = kws[2]
			case "extintf":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Extintf = kws[2]
			case "protocol":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Protocol = kws[2]
			case "portforward":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Portforward = kws[2]
			case "extport":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Extport, err = strconv.Atoi(kws[2])
				if err != nil {
					return fmt.Errorf("Can't decode number %q at line %d", kws[2], line)
				}
			case "mappedport":
				err = kwsl(kws, 3, line); if err != nil { return err }
				v.Mappedport, err = strconv.Atoi(kws[2])
				if err != nil {
					return fmt.Errorf("Can't decode number %q at line %d", kws[2], line)
				}
			case "color":
				/* con't care */
			default:
				return fmt.Errorf("Unexpected word %q at line %d", kws[1], line)
			}
		case "next":
			return nil
		default:
			return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
		}
	}
}

/* Process "config firewall addgrp" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallVip()(error) {
	var kws []string
	var line int
	var err error
	var v *Vip
	var index *Index

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "edit":

			/* Expect id of Object */
			err = kwsl(kws, 2, line); if err != nil { return err }
			v = &Vip{}
			v.Name = kws[1]

			/* Decode object properties */
			err = fg.EditFirewallVip(v)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Vip_by_name[v.Name] = v

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kws[0], line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallServiceGroup(s *ServiceGroup)(error) {
	var kws []string
	var line int
	var err error

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "set":
			err = kwsl(kws, 2, line); if err != nil { return err }
			switch kws[1] {
			case "member":
				err = kwsl(kws, 3, line); if err != nil { return err }
				s.member = kws[2:]
			default:
				return fmt.Errorf("Unexpected word %q at line %d", kws[1], line)
			}
		case "next":
			return nil
		default:
			return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
		}
	}
}

/* Process "config firewall service custom" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallServiceGroup()(error) {
	var kws []string
	var line int
	var err error
	var s *ServiceGroup
	var index *Index

	for {

		/* read next word */
		kws, line, err = fg.s.NextLine(); if err != nil { return err }

		/* Process keyword */
		switch kws[0] {
		case "edit":

			/* Expect id of Object */
			err = kwsl(kws, 2, line); if err != nil { return err }
			s = &ServiceGroup{}
			s.Name = kws[1]

			/* Decode object properties */
			err = fg.EditFirewallServiceGroup(s)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.ServiceGroup_by_name[s.Name] = s

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kws[0], line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallServiceCustom(s *Service)(error) {
	var kws []string
	var line int
	var port string
	var err error
	var v1 int
	var v2 int
	var w []string

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "set":
			err = kwsl(kws, 2, line); if err != nil { return err }
			switch kws[1] {
			case "comment":
				err = kwsl(kws, 3, line); if err != nil { return err }
				s.Comment = kws[2]
			case "category":
				err = kwsl(kws, 3, line); if err != nil { return err }
				s.Category = kws[2]
			case "protocol":
				err = kwsl(kws, 3, line); if err != nil { return err }
				s.Protocol = kws[2]
			case "protocol-number":
				err = kwsl(kws, 3, line); if err != nil { return err }
				s.Protocol_number, err = strconv.Atoi(kws[2])
				if err != nil {
					return fmt.Errorf("Can't decode protocol-number %q at line %d", kws[2], line)
				}
			case "tcp-portrange",
			     "udp-portrange":
				err = kwsl(kws, 3, line); if err != nil { return err }
				for _, port = range kws[2:] {
					for _, port = range strings.Split(port, ":") {
						if strings.Contains(port, "-") {
							w = strings.Split(port, "-")
							if len(w) != 2 {
								return fmt.Errorf("Can't decode port-range %q at line %d", port, line)
							}
							v1, err = strconv.Atoi(w[0])
							if err != nil {
								return fmt.Errorf("Can't decode port %q at line %d", w[0], line)
							}
							v2, err = strconv.Atoi(w[1])
							if err != nil {
								return fmt.Errorf("Can't decode port %q at line %d", w[1], line)
							}
							if kws[1] == "tcp-portrange" {
								s.Tcp_portrange = append(s.Tcp_portrange, []int{v1,v2})
							} else {
								s.Udp_portrange = append(s.Udp_portrange, []int{v1,v2})
							}
						} else {
							v1, err = strconv.Atoi(port)
							if err != nil {
								return fmt.Errorf("Can't decode port %q at line %d", port, line)
							}
							if kws[1] == "tcp-portrange" {
								s.Tcp_portrange = append(s.Tcp_portrange, v1)
							} else {
								s.Udp_portrange = append(s.Udp_portrange, v1)
							}
						}
					}
				}
			case "visibility",
			     "icmptype",
			     "proxy":
				/* don't care */
			default:
				return fmt.Errorf("Unexpected word %q at line %d", kws[1], line)
			}
		case "unset":
			/* don't care */
		case "next":
			return nil
		default:
			return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
		}
	}
}

/* Process "config firewall service custom" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallServiceCustom()(error) {
	var kws []string
	var line int
	var err error
	var s *Service
	var index *Index

	for {

		/* read next word */
		kws, line, err = fg.s.NextLine(); if err != nil { return err }

		/* Process keyword */
		switch kws[0] {
		case "edit":

			/* Expect id of Object */
			err = kwsl(kws, 2, line); if err != nil { return err }
			s = &Service{}
			s.Name = kws[1]

			/* Decode object properties */
			err = fg.EditFirewallServiceCustom(s)
			if err != nil {
				return err
			}

			/* Fix ALL rule to match any port */
			if s.Protocol == "IP" && len(s.Tcp_portrange) == 0 && len(s.Tcp_portrange) == 0 {
				s.Tcp_portrange = append(s.Tcp_portrange, []int{1, 65535})
				s.Udp_portrange = append(s.Udp_portrange, []int{1, 65535})
			}
			if len(s.Tcp_portrange) > 0 && s.Protocol == "" {
				s.Protocol = "TCP"
			}
			if len(s.Udp_portrange) > 0 && s.Protocol == "" {
				s.Protocol = "UDP"
			}
			if s.Protocol_number > 0 && s.Protocol == "" {
				s.Protocol = s.Name
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Service_by_name[s.Name] = s

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kws[0], line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallAddgrp(g *Group)(error) {
	var kws []string
	var err error
	var line int

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "set":
			err = kwsl(kws, 2, line); if err != nil { return err }
			switch kws[1] {
			case "uuid":
				err = kwsl(kws, 3, line); if err != nil { return err }
				g.Uuid = kws[2]
			case "comment":
				err = kwsl(kws, 3, line); if err != nil { return err }
				g.Comment = kws[2]
			case "member":
				err = kwsl(kws, 3, line); if err != nil { return err }
				g.member = kws[2:]
			case "allow-routing":
				/* don't care */
			default:
				return fmt.Errorf("Unexpected word %q at line %d", kws[1], line)
			}
		case "next":
			return nil
		default:
			return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
		}
	}
}

/* Process "config firewall addgrp" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallAddgrp()(error) {
	var kws []string
	var line int
	var err error
	var g *Group
	var index *Index

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "edit":

			/* Expect id of Object */
			err = kwsl(kws, 2, line); if err != nil { return err }
			g = &Group{}
			g.Name = kws[1]

			/* Decode object properties */
			err = fg.EditFirewallAddgrp(g)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Group_by_name[g.Name] = g

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kws[0], line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallPolicy(p *Policy)(error) {
	var kws []string
	var err error
	var do_ignore bool
	var line int

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "set":
			err = kwsl(kws, 2, line); if err != nil { return err }
			switch kws[1] {
			case "uuid":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Uuid = kws[2]
			case "comments":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Comments = kws[2]
			case "name":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Name = kws[2]
			case "srcintf":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Srcintf = kws[2]
			case "dstintf":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Dstintf = kws[2]
			case "action":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Action = kws[2]
			case "schedule":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Schedule = kws[2]
			case "logtraffic":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Logtraffic = kws[2]
			case "srcaddr":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.srcaddr = kws[2:]
			case "dstaddr":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.dstaddr = kws[2:]
			case "service":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.service = kws[2:]
			case "groups":
				err = kwsl(kws, 3, line); if err != nil { return err }
				p.Groups = kws[2:]
			case "status":
				err = kwsl(kws, 3, line); if err != nil { return err }
				if kws[2] == "disable" {
					do_ignore = true
				}
			case "ips-sensor",
			     "ippool",
			     "poolname",
			     "nat",
			     "ssl-ssh-profile",
			     "application-list",
			     "profile-protocol-options",
			     "webfilter-profile",
			     "utm-status",
			     "internet-service",
			     "internet-service-name",
			     "users":
				/* don't care */
			default:
				return fmt.Errorf("Unexpected word %q at line %d", kws[1], line)
			}
		case "next":
			if do_ignore {
				return ignore
			}
			return nil
		default:
			return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
		}
	}
}

/* Process "config firewall address" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallPolicy()(error) {
	var kws []string
	var err error
	var p *Policy
	var index *Index
	var line int

	for {

		/* read next word */
		kws, line, err = fg.s.NextLine(); if err != nil {	return err }

		/* Process keyword */
		switch kws[0] {
		case "edit":

			/* Expect id of Object */
			err = kwsl(kws, 2, line); if err != nil { return err }
			p = &Policy{}
			p.Id, err = strconv.Atoi(kws[1])
			if err != nil {
				return fmt.Errorf("Can't decode policy id %q at line %d", kws[1], line)
			}

			/* Decode object properties */
			err = fg.EditFirewallPolicy(p)
			if err != nil {
				if err == ignore {
					p = nil
				} else {
					return err
				}
			}

			/* Index object */
			if p != nil {
				index = get_vdom(fg.current_vdom)
				index.Policy_list = append(index.Policy_list, p)
				p = nil
			}

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kws[0], line)
		}
	}
}

/* Process object configuration. There is a Edit section parser,
 * Process keywords until end
 */
func (fg *FG)EditFirewallAddressObject(o *Object)(error) {
	var kws []string
	var err error
	var ip string
	var mask string
	var i net.IP
	var m net.IP
	var n net.IPNet
	var line int

	for {
		kws, line, err = fg.s.NextLine(); if err != nil { return err }
		switch kws[0] {
		case "set":
			err = kwsl(kws, 2, line); if err != nil { return err }
			switch kws[1] {
			case "uuid":
				err = kwsl(kws, 3, line); if err != nil { return err }
				o.Uuid = kws[2]
			case "start-ip":
				err = kwsl(kws, 3, line); if err != nil { return err }
				i = net.ParseIP(kws[2])
				if i == nil {
					return fmt.Errorf("Can't decode ip network: %q at line %d", ip, line)
				}
				o.Range_start = i.String()
			case "end-ip":
				err = kwsl(kws, 3, line); if err != nil { return err }
				i = net.ParseIP(kws[2])
				if i == nil {
					return fmt.Errorf("Can't decode ip network: %q at line %d", ip, line)
				}
				o.Range_end = i.String()
			case "fqdn":
				err = kwsl(kws, 3, line); if err != nil { return err }
				o.Fqdn = kws[2]
			case "macaddr":
				err = kwsl(kws, 3, line); if err != nil { return err }
				o.Macaddr = kws[2]
			case "type",
			     "sub-type",
			     "associated-interface",
			     "allow-routing":
				/* dont care */
			case "subnet":
				err = kwsl(kws, 4, line); if err != nil { return err }
				i = net.ParseIP(kws[2])
				if i == nil {
					return fmt.Errorf("Can't decode ip network: %q at line %d", ip, line)
				}
				m = net.ParseIP(kws[3])
				if m == nil {
					return fmt.Errorf("Can't decode mask: %q at line %d", mask, line)
				}
				n = net.IPNet{
					IP: i,
					Mask: net.IPMask(m),
				}
				o.Network = n.String()
			case "comment":
				err = kwsl(kws, 3, line); if err != nil { return err }
				o.Comment = kws[2]
			default:
				return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
			}
		case "next":
			return nil
		default:
			return fmt.Errorf("Unexpected word %q at line %d", kws[0], line)
		}
	}
}

/* Process "config firewall address" section is a
 * list of edit section which define objects
 */
func (fg *FG)ConfigFirewallAddress()(error) {
	var kws []string
	var err error
	var o *Object
	var index *Index
	var line int

	for {

		/* read next word */
		kws, line, err = fg.s.NextLine(); if err != nil { return err }

		/* Process keyword */
		switch kws[0] {
		case "edit":

			/* Expect name of Object */
			err = kwsl(kws, 2, line); if err != nil { return err }
			o = &Object{}
			o.Name = kws[1]

			/* Decode object properties */
			err = fg.EditFirewallAddressObject(o)
			if err != nil {
				return err
			}

			/* Index object */
			index = get_vdom(fg.current_vdom)
			index.Object_by_name[o.Name] = o

		case "end":
			return nil

		default:
			return fmt.Errorf("Expect \"edit\" or \"end\" keyword, got %q at line %d", kws[0], line)
		}
	}
}

/* Process VDOM section. Expect list of edit */
func (fg *FG)ConfigVdom()(error) {
	var kws []string
	var line int
	var err error

	for {

		/* read next word */
		kws, line, err = fg.s.NextLine(); if err != nil {	return err }

		/* Process keyword */
		switch kws[0] {
		case "edit":

			/* Expect name of VDOM */
			err = kwsl(kws, 2, line); if err != nil { return err }
			fg.current_vdom = kws[1]

			/* Expect list of config */
			err = fg.ConfigList(false)
			if err != nil {
				return err
			}

		case "end": /* end of config */
			fg.current_vdom = ""
			return nil
		}
	}
}

/* Process config section */
func (fg *FG)ConfigList(alloweof bool)(error) {
	var err error
	var line int
	var kws []string

	for {

		/* read config line */
		kws, line, err = fg.s.NextLine()
		if err != nil {
			if err == io.EOF && alloweof {
				return nil
			}
			return err
		}

		/* we expect config section */
		if kws[0] != "config" {
			fg.s.PushLine(kws)
			return nil
		}

		/* At least one word */
		if len(kws) < 2 {
			return fmt.Errorf("Expect config kind at line %d", line)
		}

		/* Handle known config section */
		switch kws[1] {

		/* config vdom */
		case "vdom": err = fg.ConfigVdom(); if err != nil { return err }

		/* config firewall */
		case "firewall":
			err = kwsl(kws, 3, line); if err != nil { return err }
			switch kws[2] {

			/* config firewall address */
			case "address": err = fg.ConfigFirewallAddress(); if err != nil { return err }

			/* config firewall policy */
			case "policy": err = fg.ConfigFirewallPolicy(); if err != nil { return err }

			/* config firewall addrgrp */
			case "addrgrp": err = fg.ConfigFirewallAddgrp(); if err != nil { return err }

			/* config firewall vip */
			case "vip": err = fg.ConfigFirewallVip(); if err != nil { return err }

			/* config firewall service */
			case "service":
				err = kwsl(kws, 4, line); if err != nil { return err }
				switch kws[3] {

				/* config firewall service custom */
				case "custom": err = fg.ConfigFirewallServiceCustom(); if err != nil { return err }

				/* config firewall service custom */
				case "group": fg.ConfigFirewallServiceGroup()

				/* fallback */
				default: fg.ConfigEnd()
				}

			/* fallback */
			default: fg.ConfigEnd()
			}

		/* fallback */
		default: fg.ConfigEnd()
		}
	}
}
