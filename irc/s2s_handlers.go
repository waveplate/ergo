// Copyright (c) 2026 Ergo Developers
// released under the MIT license

package irc

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ergochat/ergo/irc/modes"
	"github.com/ergochat/ergo/irc/utils"
	"github.com/ergochat/irc-go/ircmsg"
)

// HandleLine processes an incoming line/message from a ServerLink.
func (s2s *S2SManager) HandleLine(link *ServerLink, rawLine string, msg ircmsg.Message) error {
	command := strings.ToUpper(msg.Command)

	// Pre-handshake commands
	if !link.handshakeDone {
		switch command {
		case "PASS":
			return s2s.handlePass(link, msg)
		case "CAPAB":
			return s2s.handleCapab(link, msg)
		case "SERVER":
			return s2s.handleServer(link, msg)
		case "SVINFO":
			return s2s.handleSVINFO(link, msg)
		case "ERROR":
			s2s.server.logger.Error("s2s", "Received ERROR from link during handshake", link.remoteName, strings.Join(msg.Params, " "))
			return fmt.Errorf("peer error: %v", msg.Params)
		default:
			s2s.server.logger.Debug("s2s", "Unexpected command during handshake", command)
			return nil
		}
	}

	// Post-handshake runtime commands
	switch command {
	case "PING":
		return s2s.handlePing(link, msg)
	case "PONG":
		return s2s.handlePong(link, msg)
	case "SID":
		return s2s.handleSID(link, msg)
	case "SQUIT":
		return s2s.handleSQuit(link, msg)
	case "UID":
		return s2s.handleUID(link, msg, false)
	case "EUID":
		return s2s.handleUID(link, msg, true)
	case "NICK":
		return s2s.handleNick(link, msg)
	case "QUIT":
		return s2s.handleQuit(link, msg)
	case "KILL":
		return s2s.handleKill(link, msg)
	case "AWAY":
		return s2s.handleAway(link, msg)
	case "SJOIN":
		return s2s.handleSJoin(link, msg)
	case "JOIN":
		return s2s.handleJoin(link, msg)
	case "PART":
		return s2s.handlePart(link, msg)
	case "KICK":
		return s2s.handleKick(link, msg)
	case "TMODE", "MODE":
		return s2s.handleTMode(link, msg)
	case "BMASK":
		return s2s.handleBMask(link, msg)
	case "TB", "TOPIC":
		return s2s.handleTopic(link, msg)
	case "PRIVMSG":
		return s2s.handlePrivmsg(link, msg)
	case "NOTICE":
		return s2s.handleNotice(link, msg)
	case "ENCAP":
		return s2s.handleEncap(link, msg)
	case "ERROR":
		s2s.server.logger.Warning("s2s", "Received ERROR from peer", link.remoteName, strings.Join(msg.Params, " "))
		return nil
	default:
		s2s.server.logger.Debug("s2s", "Unhandled S2S command", command, strings.Join(msg.Params, " "))
		return nil
	}
}

// PASS <password> TS 6 :<sid>
func (s2s *S2SManager) handlePass(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 4 {
		return fmt.Errorf("malformed PASS line: expected at least 4 params")
	}

	pass := msg.Params[0]
	if pass == "*" {
		pass = ""
	}
	tsProtocol := msg.Params[1]
	tsVersion := msg.Params[2]
	sid := strings.ToUpper(msg.Params[3])

	if tsProtocol != "TS" || tsVersion != "6" {
		return fmt.Errorf("unsupported TS version: %s %s", tsProtocol, tsVersion)
	}

	if !IsValidSID(sid) {
		return fmt.Errorf("invalid SID format: %s", sid)
	}

	if sid == s2s.server.sid {
		return fmt.Errorf("SID collision with our own SID: %s", sid)
	}

	// Password validation
	if link.inbound {
		// Find matching link config if present
		cfg := s2s.FindLinkConfig(sid, "")
		if cfg != nil && cfg.ReceivePassword != "" {
			if pass != cfg.ReceivePassword {
				return fmt.Errorf("invalid link password for SID %s", sid)
			}
			link.config = cfg
		}
	} else {
		if link.config != nil && link.config.ReceivePassword != "" {
			if pass != link.config.ReceivePassword {
				return fmt.Errorf("invalid link password from peer %s", link.config.Name)
			}
		}
	}

	link.remoteSID = sid
	return nil
}

// CAPAB :<caps...>
func (s2s *S2SManager) handleCapab(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) > 0 {
		tokens := strings.Fields(msg.Params[0])
		for _, token := range tokens {
			link.capabs.Add(token)
		}
	}
	return nil
}

// SERVER <servername> <hopcount> :<description>
func (s2s *S2SManager) handleServer(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 3 {
		return fmt.Errorf("malformed SERVER line")
	}

	name := msg.Params[0]
	hopCount, _ := strconv.Atoi(msg.Params[1])
	desc := msg.Params[2]

	link.remoteName = name
	link.remoteDesc = desc

	remoteNode := &ServerNode{
		Name:           name,
		NameCasefolded: strings.ToLower(name),
		SID:            link.remoteSID,
		Description:    desc,
		HopCount:       hopCount,
		NextHop:        link,
		IsDirect:       true,
		Ctime:          time.Now().UTC(),
	}
	link.remoteNode = remoteNode

	s2s.RegisterServer(remoteNode)
	return nil
}

// SVINFO 6 6 0 :<current_timestamp>
func (s2s *S2SManager) handleSVINFO(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 4 {
		return fmt.Errorf("malformed SVINFO line")
	}

	link.handshakeDone = true

	// If this was an inbound link, send our handshake response now
	if link.inbound {
		sendPass := "*"
		if link.config != nil && link.config.SendPassword != "" {
			sendPass = link.config.SendPassword
		}
		link.SendLine(fmt.Sprintf("PASS %s TS 6 :%s", sendPass, s2s.server.sid))
		link.SendLine("CAPAB :QS EX CHW IE ENCAP EUID TB KNOCK")
		link.SendLine(fmt.Sprintf("SERVER %s 1 :%s", s2s.server.name, s2s.server.name))
		link.SendLine(fmt.Sprintf("SVINFO 6 6 0 :%d", time.Now().Unix()))
	}

	// Announce this new server to all other direct links
	s2s.BroadcastMsg(ircmsg.MakeMessage(nil, s2s.server.sid, "SID", link.remoteName, "2", link.remoteSID, link.remoteDesc), link)

	// Handshake complete, burst our state to the link
	s2s.BurstState(link)
	link.StartPingTicker()
	return nil
}

// PING <source> :<target>
func (s2s *S2SManager) handlePing(link *ServerLink, msg ircmsg.Message) error {
	source := msg.Source
	if source == "" && len(msg.Params) > 0 {
		source = msg.Params[0]
	}

	target := ""
	if len(msg.Params) > 1 {
		target = msg.Params[1]
	} else if len(msg.Params) > 0 {
		target = msg.Params[0]
	}

	// If PING is meant for us, reply with PONG
	if target == "" || target == s2s.server.sid || target == s2s.server.name || target == "*" {
		link.Send(s2s.server.sid, "PONG", s2s.server.sid, source)
		return nil
	}

	// Otherwise forward PING towards target SID
	s2s.SendToSID(target, msg)
	return nil
}

// PONG <source> :<target>
func (s2s *S2SManager) handlePong(link *ServerLink, msg ircmsg.Message) error {
	if !link.burstDone {
		link.burstDone = true
		s2s.server.logger.Info("s2s", "Burst completed and acknowledged by link", link.remoteName, link.remoteSID)
	}
	return nil
}

// :<uplink_sid> SID <servername> <hopcount> <sid> :<description>
func (s2s *S2SManager) handleSID(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 4 {
		return nil
	}

	name := msg.Params[0]
	hopCount, _ := strconv.Atoi(msg.Params[1])
	sid := strings.ToUpper(msg.Params[2])
	desc := msg.Params[3]

	node := &ServerNode{
		Name:           name,
		NameCasefolded: strings.ToLower(name),
		SID:            sid,
		Description:    desc,
		HopCount:       hopCount,
		UplinkSID:      msg.Source,
		NextHop:        link,
		Ctime:          time.Now().UTC(),
	}

	s2s.RegisterServer(node)

	// Propagate to other direct links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<source_sid> SQUIT <target_sid> :<reason>
func (s2s *S2SManager) handleSQuit(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}
	targetSID := strings.ToUpper(msg.Params[0])
	reason := msg.Params[1]

	s2s.HandleServerSplit(targetSID, reason)
	s2s.BroadcastMsg(msg, link)
	return nil
}

// UID / EUID
func (s2s *S2SManager) handleUID(link *ServerLink, msg ircmsg.Message, isEUID bool) error {
	minParams := 9
	if isEUID {
		minParams = 11
	}
	if len(msg.Params) < minParams {
		return nil
	}

	nick := msg.Params[0]
	// hopCount, _ := strconv.Atoi(msg.Params[1])
	nickTSUnix, _ := strconv.ParseInt(msg.Params[2], 10, 64)
	nickTS := time.Unix(nickTSUnix, 0).UTC()
	umodesStr := msg.Params[3]
	username := msg.Params[4]
	hostname := msg.Params[5]
	ipStr := msg.Params[6]
	uid := strings.ToUpper(msg.Params[7])

	var realhost, account, realname string
	if isEUID {
		realhost = msg.Params[8]
		account = msg.Params[9]
		realname = msg.Params[10]
	} else {
		realname = msg.Params[8]
	}

	if realhost == "*" {
		realhost = ""
	}
	if account == "*" {
		account = ""
	}

	serverSID := msg.Source
	if serverSID == "" && len(uid) >= 3 {
		serverSID = uid[:3]
	}

	// Parse modes
	var umodes modes.ModeSet
	for _, ch := range umodesStr {
		if ch != '+' {
			umodes.SetMode(modes.Mode(ch), true)
		}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		ip = utils.IPv4LoopbackAddress
	}

	// Check for nickname collision
	existing := s2s.server.clients.Get(nick)
	if existing != nil && existing.UID() != uid {
		existingTS := existing.NickTS()
		if nickTS.Before(existingTS) {
			// Incoming is older, incoming wins!
			if existing.IsRemote() {
				s2s.server.clients.Remove(existing)
				s2s.BroadcastKill(s2s.server.sid, existing, "Nickname collision")
			} else {
				existing.Quit("Killed: Nickname collision", nil, nil)
				existing.destroy(nil)
			}
		} else if nickTS.After(existingTS) {
			// Existing is older, existing wins!
			link.Send(s2s.server.sid, "KILL", uid, fmt.Sprintf("%s!%s (Nickname collision)", s2s.server.name, s2s.server.name))
			return nil
		} else {
			// Equal timestamps, kill both!
			link.Send(s2s.server.sid, "KILL", uid, fmt.Sprintf("%s!%s (Nickname collision)", s2s.server.name, s2s.server.name))
			if existing.IsRemote() {
				s2s.server.clients.Remove(existing)
			} else {
				existing.Quit("Killed: Nickname collision", nil, nil)
				existing.destroy(nil)
			}
			return nil
		}
	}

	client := NewRemoteClient(s2s.server, uid, serverSID, nick, username, hostname, realhost, ip, umodes, realname, account, nickTS, link)
	if err := s2s.server.clients.AddRemoteClient(client); err != nil {
		s2s.server.logger.Error("s2s", "Could not add remote client", nick, uid, err.Error())
		return nil
	}

	s2s.server.stats.AddRegistered(client.HasMode(modes.Invisible), client.HasMode(modes.Operator))

	// Forward UID to other direct links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<uid> NICK <newnick> <newnickTS>
func (s2s *S2SManager) handleNick(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}

	uid := msg.Source
	newNick := msg.Params[0]
	newNickTSUnix, _ := strconv.ParseInt(msg.Params[1], 10, 64)
	newNickTS := time.Unix(newNickTSUnix, 0).UTC()

	client := s2s.server.clients.GetByUID(uid)
	if client == nil {
		return nil
	}

	oldNickMask := client.NickMaskString()

	// Collision check
	existing := s2s.server.clients.Get(newNick)
	if existing != nil && existing.UID() != uid {
		existingTS := existing.NickTS()
		if newNickTS.Before(existingTS) {
			if existing.IsRemote() {
				s2s.server.clients.Remove(existing)
				s2s.BroadcastKill(s2s.server.sid, existing, "Nickname collision")
			} else {
				existing.Quit("Killed: Nickname collision", nil, nil)
				existing.destroy(nil)
			}
		} else {
			link.Send(s2s.server.sid, "KILL", uid, fmt.Sprintf("%s (Nickname collision)", s2s.server.name))
			return nil
		}
	}

	_ = s2s.server.clients.SetRemoteNick(client, newNick, newNickTS)

	// Notify local channel friends
	for session := range client.Friends() {
		session.Send(nil, oldNickMask, "NICK", newNick)
	}

	// Forward to other links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<uid> QUIT :<reason>
func (s2s *S2SManager) handleQuit(link *ServerLink, msg ircmsg.Message) error {
	uid := msg.Source
	reason := ""
	if len(msg.Params) > 0 {
		reason = msg.Params[0]
	}

	client := s2s.server.clients.GetByUID(uid)
	if client == nil {
		return nil
	}

	mask := client.NickMaskString()

	// Send QUIT to local channel friends
	for session := range client.Friends() {
		session.Send(nil, mask, "QUIT", reason)
	}

	// Remove from all channels
	for _, ch := range client.Channels() {
		ch.Quit(client)
	}

	// Remove from ClientManager
	s2s.server.clients.Remove(client)
	s2s.server.stats.Remove(true, client.HasMode(modes.Invisible), client.HasMode(modes.Operator))

	// Forward to other links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<killer> KILL <target_uid> :<path> (<reason>)
func (s2s *S2SManager) handleKill(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 1 {
		return nil
	}

	targetUID := msg.Params[0]
	reason := "Killed"
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	target := s2s.server.clients.GetByUID(targetUID)
	if target == nil {
		target = s2s.server.clients.Get(targetUID)
	}
	if target == nil {
		return nil
	}

	if !target.IsRemote() {
		// Local client killed by remote oper/server
		target.Quit(fmt.Sprintf("Killed (%s)", reason), nil, nil)
		target.destroy(nil)
	} else {
		// Remote client killed
		mask := target.NickMaskString()
		for session := range target.Friends() {
			session.Send(nil, mask, "QUIT", fmt.Sprintf("Killed (%s)", reason))
		}
		for _, ch := range target.Channels() {
			ch.Quit(target)
		}
		s2s.server.clients.Remove(target)
		s2s.server.stats.Remove(true, target.HasMode(modes.Invisible), target.HasMode(modes.Operator))
	}

	// Forward to other links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<uid> AWAY [<reason>]
func (s2s *S2SManager) handleAway(link *ServerLink, msg ircmsg.Message) error {
	uid := msg.Source
	client := s2s.server.clients.GetByUID(uid)
	if client == nil {
		return nil
	}

	awayMsg := ""
	if len(msg.Params) > 0 {
		awayMsg = msg.Params[0]
	}

	client.stateMutex.Lock()
	client.awayMessage = awayMsg
	client.stateMutex.Unlock()

	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<source> SJOIN <chanTS> <channel> <modes> [params...] :<members>
func (s2s *S2SManager) handleSJoin(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 3 {
		return nil
	}

	chanTSUnix, _ := strconv.ParseInt(msg.Params[0], 10, 64)
	chname := msg.Params[1]
	modesStr := msg.Params[2]
	membersStr := msg.Params[len(msg.Params)-1]

	ch := s2s.server.channels.GetOrCreate(chname, chanTSUnix)
	if ch == nil {
		return nil
	}

	localTS := ch.CreatedTime().Unix()

	// TS conflict resolution
	if chanTSUnix < localTS {
		// Incoming channel is older! Update TS and overwrite simple modes
		ch.SetCreatedTime(time.Unix(chanTSUnix, 0).UTC())
	}

	// Apply channel modes if incoming TS <= localTS
	if chanTSUnix <= localTS && len(modesStr) > 1 && modesStr != "+" {
		for _, m := range modesStr {
			if m != '+' {
				ch.flags.SetMode(modes.Mode(m), true)
			}
		}
	}

	// Parse members
	tokens := strings.Fields(membersStr)
	for _, token := range tokens {
		if len(token) < 9 {
			continue
		}
		uid := token[len(token)-9:]
		prefixes := token[:len(token)-9]

		client := s2s.server.clients.GetByUID(uid)
		if client == nil {
			continue
		}

		var memberModes modes.Modes
		for _, p := range prefixes {
			switch p {
			case '@':
				memberModes = append(memberModes, modes.ChannelOperator)
			case '%':
				memberModes = append(memberModes, modes.Halfop)
			case '+':
				memberModes = append(memberModes, modes.Voice)
			case '~':
				memberModes = append(memberModes, modes.ChannelFounder)
			case '&':
				memberModes = append(memberModes, modes.ChannelAdmin)
			}
		}

		ch.AddRemoteMember(client, memberModes)
	}

	// Forward SJOIN to other direct links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<uid> JOIN <chanTS> <channel> +
func (s2s *S2SManager) handleJoin(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}

	uid := msg.Source
	chanTSUnix, _ := strconv.ParseInt(msg.Params[0], 10, 64)
	chname := msg.Params[1]

	client := s2s.server.clients.GetByUID(uid)
	if client == nil {
		return nil
	}

	ch := s2s.server.channels.GetOrCreate(chname, chanTSUnix)
	if ch == nil {
		return nil
	}

	ch.AddRemoteMember(client, nil)

	// Send JOIN line to local channel members
	mask := client.NickMaskString()
	for _, member := range ch.Members() {
		for _, session := range member.Sessions() {
			session.Send(nil, mask, "JOIN", ch.Name())
		}
	}

	// Forward to other links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<uid> PART <channel> :<reason>
func (s2s *S2SManager) handlePart(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 1 {
		return nil
	}

	uid := msg.Source
	chname := msg.Params[0]
	reason := ""
	if len(msg.Params) > 1 {
		reason = msg.Params[1]
	}

	client := s2s.server.clients.GetByUID(uid)
	if client == nil {
		return nil
	}

	ch := s2s.server.channels.Get(chname)
	if ch == nil {
		return nil
	}

	mask := client.NickMaskString()
	for _, member := range ch.Members() {
		for _, session := range member.Sessions() {
			if reason != "" {
				session.Send(nil, mask, "PART", ch.Name(), reason)
			} else {
				session.Send(nil, mask, "PART", ch.Name())
			}
		}
	}

	ch.Quit(client)

	// Forward to other links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<kicker> KICK <channel> <target_uid> :<reason>
func (s2s *S2SManager) handleKick(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}

	chname := msg.Params[0]
	targetUID := msg.Params[1]
	reason := ""
	if len(msg.Params) > 2 {
		reason = msg.Params[2]
	}

	ch := s2s.server.channels.Get(chname)
	target := s2s.server.clients.GetByUID(targetUID)
	if target == nil {
		target = s2s.server.clients.Get(targetUID)
	}
	if ch == nil || target == nil {
		return nil
	}

	kickerMask := msg.Source
	if kickerClient := s2s.server.clients.GetByUID(msg.Source); kickerClient != nil {
		kickerMask = kickerClient.NickMaskString()
	}

	for _, member := range ch.Members() {
		for _, session := range member.Sessions() {
			session.Send(nil, kickerMask, "KICK", ch.Name(), target.Nick(), reason)
		}
	}

	ch.Quit(target)

	// Forward to other links
	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<source> TB <channel> <topicTS> <topicSetBy> :<topic>
func (s2s *S2SManager) handleTopic(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}

	chname := msg.Params[0]
	ch := s2s.server.channels.Get(chname)
	if ch == nil {
		return nil
	}

	var topicTSUnix int64
	var topicSetBy, topic string

	if msg.Command == "TB" && len(msg.Params) >= 4 {
		topicTSUnix, _ = strconv.ParseInt(msg.Params[1], 10, 64)
		topicSetBy = msg.Params[2]
		topic = msg.Params[3]
	} else if len(msg.Params) >= 2 {
		topicTSUnix = time.Now().Unix()
		topicSetBy = msg.Source
		topic = msg.Params[len(msg.Params)-1]
	}

	ch.stateMutex.Lock()
	if topicTSUnix >= ch.topicSetTime.Unix() || ch.topic == "" {
		ch.topic = topic
		ch.topicSetBy = topicSetBy
		ch.topicSetTime = time.Unix(topicTSUnix, 0).UTC()
	}
	ch.stateMutex.Unlock()

	for _, member := range ch.Members() {
		for _, session := range member.Sessions() {
			session.Send(nil, topicSetBy, "TOPIC", ch.Name(), topic)
		}
	}

	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<source> TMODE <chanTS> <channel> <modes> [params...]
func (s2s *S2SManager) handleTMode(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}

	var chname, modesStr string
	var args []string

	if msg.Command == "TMODE" && len(msg.Params) >= 3 {
		// chanTS := msg.Params[0]
		chname = msg.Params[1]
		modesStr = msg.Params[2]
		args = msg.Params[3:]
	} else {
		chname = msg.Params[0]
		if len(msg.Params) > 1 {
			modesStr = msg.Params[1]
			args = msg.Params[2:]
		}
	}

	ch := s2s.server.channels.Get(chname)
	if ch == nil {
		return nil
	}

	sourceMask := msg.Source
	if srcClient := s2s.server.clients.GetByUID(msg.Source); srcClient != nil {
		sourceMask = srcClient.NickMaskString()
	}

	modeArgs := append([]string{ch.Name(), modesStr}, args...)
	for _, member := range ch.Members() {
		for _, session := range member.Sessions() {
			session.Send(nil, sourceMask, "MODE", modeArgs...)
		}
	}

	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<source> BMASK <chanTS> <channel> <type> :<masks...>
func (s2s *S2SManager) handleBMask(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 4 {
		return nil
	}

	chname := msg.Params[1]
	maskType := msg.Params[2]
	masksStr := msg.Params[3]

	ch := s2s.server.channels.Get(chname)
	if ch == nil {
		return nil
	}

	masks := strings.Fields(masksStr)
	var maskMode modes.Mode
	switch maskType {
	case "b":
		maskMode = modes.BanMask
	case "e":
		maskMode = modes.ExceptMask
	case "I":
		maskMode = modes.InviteMask
	}
	if maskMode != 0 {
		for _, mask := range masks {
			ch.lists[maskMode].Add(mask, msg.Source, "")
		}
	}

	s2s.BroadcastMsg(msg, link)
	return nil
}

// :<sender_uid> PRIVMSG <target> :<message>
func (s2s *S2SManager) handlePrivmsg(link *ServerLink, msg ircmsg.Message) error {
	return s2s.deliverMessage(link, msg, "PRIVMSG")
}

// :<sender_uid> NOTICE <target> :<message>
func (s2s *S2SManager) handleNotice(link *ServerLink, msg ircmsg.Message) error {
	return s2s.deliverMessage(link, msg, "NOTICE")
}

func (s2s *S2SManager) deliverMessage(link *ServerLink, msg ircmsg.Message, command string) error {
	if len(msg.Params) < 2 {
		return nil
	}

	target := msg.Params[0]
	text := msg.Params[1]

	sender := s2s.server.clients.GetByUID(msg.Source)
	senderMask := msg.Source
	if sender != nil {
		senderMask = sender.NickMaskString()
	}

	if len(target) > 0 && target[0] == '#' {
		// Channel message
		ch := s2s.server.channels.Get(target)
		if ch != nil {
			for _, member := range ch.Members() {
				for _, session := range member.Sessions() {
					session.Send(nil, senderMask, command, ch.Name(), text)
				}
			}
		}
		// Forward to other direct links
		s2s.BroadcastMsg(msg, link)
	} else {
		// Private message
		targetClient := s2s.server.clients.GetByUID(target)
		if targetClient == nil {
			targetClient = s2s.server.clients.Get(target)
		}
		if targetClient != nil {
			if !targetClient.IsRemote() {
				for _, session := range targetClient.Sessions() {
					session.Send(nil, senderMask, command, targetClient.Nick(), text)
				}
			} else {
				// Target is remote on another link
				if targetClient.Link() != nil && targetClient.Link() != link {
					targetClient.Link().SendMsg(msg)
				}
			}
		}
	}
	return nil
}

// :<source> ENCAP <target> <subcommand> <params...>
func (s2s *S2SManager) handleEncap(link *ServerLink, msg ircmsg.Message) error {
	if len(msg.Params) < 2 {
		return nil
	}

	target := strings.ToUpper(msg.Params[0])
	// subcmd := strings.ToUpper(msg.Params[1])

	if target == "*" || target == s2s.server.sid || target == strings.ToUpper(s2s.server.name) {
		// Process local ENCAP if needed
	}

	if target == "*" || target != s2s.server.sid {
		s2s.BroadcastMsg(msg, link)
	}
	return nil
}
