package netship

import "testing"

func TestParseLsof(t *testing.T) {
	out := "p912\n" +
		"cnext-server\n" +
		"f23\n" +
		"PTCP\n" +
		"n127.0.0.1:8795\n" +
		"TST=LISTEN\n" +
		"f24\n" +
		"PTCP\n" +
		"n127.0.0.1:52144->140.82.112.3:443\n" +
		"TST=ESTABLISHED\n" +
		"p1400\n" +
		"cfirefox\n" +
		"f61\n" +
		"PTCP\n" +
		"n[::1]:631->[::1]:41234\n" +
		"TST=ESTABLISHED\n" +
		"f62\n" +
		"PUDP\n" +
		"n*:5353\n" +
		"p1500\n" +
		"cdead\n" +
		"f9\n" +
		"PTCP\n" +
		"n127.0.0.1:1->127.0.0.1:2\n" +
		"TST=TIME_WAIT\n"

	conns := parseLsof(out)
	if len(conns) != 5 {
		t.Fatalf("got %d sockets, want 5: %+v", len(conns), conns)
	}

	listen := conns[0]
	if listen.Pid != 912 || listen.Status != "LISTEN" || listen.Type != 1 {
		t.Fatalf("listener parsed wrong: %+v", listen)
	}
	if listen.Laddr.IP != "127.0.0.1" || listen.Laddr.Port != 8795 || listen.Raddr.Port != 0 {
		t.Fatalf("listener addresses wrong: %+v", listen.Laddr)
	}

	est := conns[1]
	if est.Raddr.IP != "140.82.112.3" || est.Raddr.Port != 443 || est.Status != "ESTABLISHED" {
		t.Fatalf("connection parsed wrong: %+v", est)
	}

	six := conns[2]
	if six.Laddr.IP != "::1" || six.Laddr.Port != 631 || six.Raddr.Port != 41234 {
		t.Fatalf("ipv6 parsed wrong: %+v", six)
	}

	udp := conns[3]
	if udp.Type != 2 || udp.Laddr.Port != 5353 || udp.Laddr.IP != "" {
		t.Fatalf("wildcard udp parsed wrong: %+v", udp)
	}

	if conns[4].Status != "TIME_WAIT" {
		t.Fatalf("teardown state lost: %+v", conns[4])
	}
}
