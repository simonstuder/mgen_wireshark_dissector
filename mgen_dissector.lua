mgen_protocol = Proto("MGen", "MGen Protocol")

message_size = ProtoField.int16("mgen.message_size", "messageSize", base.DEC)
version = ProtoField.int8("mgen.version", "version", base.DEC)
flags = ProtoField.int8("mgen.flags", "flags", base.DEC)
flow_id = ProtoField.int32("mgen.flowId", "flowId", base.DEC)
sequence = ProtoField.int32("mgen.sequence", "sequence", base.DEC)
tx_time_seconds = ProtoField.int32("mgen.tx_time_seconds", "txTimeSeconds", base.DEC)
tx_time_useconds = ProtoField.int32("mgen.tx_time_useconds", "txTimeUSeconds", base.DEC)

dst_port = ProtoField.uint16("mgen.dst_port", "dstPort", base.DEC)
dst_addr_type = ProtoField.int8("mgen.dst_addr_type", "dstAddrType", base.DEC)
dst_addr_len = ProtoField.int8("mgen.dst_addr_len", "dstAddrLen", base.DEC)
dst_addr = ProtoField.ipv4("mgen.dst_addr", "dstAddr", base.DEC)

host_port = ProtoField.int16("mgen.host_port", "hostPort", base.DEC)
host_addr_type = ProtoField.int8("mgen.host_addr_type", "hostAddrType", base.DEC)
host_addr_len = ProtoField.int8("mgen.host_addr_len", "hostAddrLen", base.DEC)
host_addr = ProtoField.ipv4("mgen.host_addr", "hostAddr", base.DEC)

latitude = ProtoField.int32("mgen.lattitude", "latitude", base.DEC)
longitude = ProtoField.int32("mgen.longitude", "longitude", base.DEC)
altitude = ProtoField.int32("mgen.altitude", "altitude", base.DEC)
gps_status = ProtoField.int8("mgen.gps_status", "gpsStatus", base.DEC)

reserved = ProtoField.int8("mgen.reserved", "reserved", base.DEC)
payload_len = ProtoField.int16("mgen.payload_len", "payloadLen", base.DEC)

payload = ProtoField.bytes("mgen.payload", "payload", base.SPACE)
padding = ProtoField.bytes("mgen.padding", "padding", base.SPACE)
checksum = ProtoField.int32("mgen.checksum", "checksum", base.DEC)

mgen_protocol.fields = {
	message_size,
	version,
	flags,
	flow_id,
	sequence,
	tx_time_seconds,
	tx_time_useconds,
	dst_port,
	dst_addr_type,
	dst_addr_len,
	dst_addr,
	host_port,
	host_addr_type,
	host_addr_len,
	host_addr,
	latitude,
	longitude,
	altitude,
	gps_status,
	reserved,
	payload_len,
	payload,
	padding,
	checksum,
}

function mgen_protocol.dissector(buffer, pinfo, tree)
	local length = buffer:len()
	if length == 0 then
		return
	end

	pinfo.cols.protocol = mgen_protocol.name

	local flow_id_raw = buffer(4, 4):uint()
	local sequence_raw = buffer(8, 4):uint()
	local subtree = tree:add(
		mgen_protocol,
		buffer(),
		"MGen, flow: "
			.. flow_id_raw
			.. ", seq: "
			.. sequence_raw
			.. ", length: "
			.. length
			.. "B("
			.. (length + 42)
			.. "B on wire)"
	)
	subtree:add(message_size, buffer(0, 2))
	subtree:add(version, buffer(2, 1))
	local flags_raw = buffer(3, 1):uint()
	local checksum_flag_raw = flags_raw & 0x01

	subtree:add(flags, buffer(3, 1))
	subtree:add(flow_id, flow_id_raw)
	subtree:add(sequence, sequence_raw)
	subtree:add(tx_time_seconds, buffer(12, 4))
	subtree:add(tx_time_useconds, buffer(16, 4))

	subtree:add(dst_port, buffer(20, 2))
	subtree:add(dst_addr_type, buffer(22, 1))
	subtree:add(dst_addr_len, buffer(23, 1))
	local dst_addr_len_raw = buffer(23, 1):uint()
	if dst_addr_len_raw > 0 then
		subtree:add(dst_addr, buffer(24, dst_addr_len_raw))
	else
		subtree:add(dst_addr, Address.ipv4("0.0.0.0"))
	end

	if length < 30 then
		return
	end
	local i = 28
	subtree:add(host_port, buffer(i, 2))
	if length < 31 then
		return
	end
	subtree:add(host_addr_type, buffer(i + 2, 1))
	if length < 32 then
		return
	end
	subtree:add(host_addr_len, buffer(i + 3, 1))
	local host_addr_len_raw = buffer(i + 3, 1):uint()
	if length < 32 + host_addr_len_raw then
		return
	end
	if host_addr_len_raw > 0 then
		subtree:add(host_addr, buffer(i + 4, host_addr_len_raw))
	else
		subtree:add(host_addr, Address.ipv4("0.0.0.0"))
	end
	i = i + 4 + host_addr_len_raw

	if length < i + 4 then
		return
	end
	local latitude_raw = buffer(i, 4):int() / 60000.0 - 180
	subtree:add(latitude, latitude_raw)
	if length < i + 8 then
		return
	end
	local longitude_raw = buffer(i + 4, 4):int() / 60000.0 - 180
	subtree:add(longitude, longitude_raw)
	if length < i + 12 then
		return
	end
	subtree:add(altitude, buffer(i + 8, 4))
	if length < i + 13 then
		return
	end
	subtree:add(gps_status, buffer(i + 12, 1))

	if length < i + 14 then
		return
	end
	subtree:add(reserved, buffer(i + 13, 1))
	if length < i + 16 then
		return
	end
	local payload_len_raw = buffer(i + 14, 2):uint()
	subtree:add(payload_len, payload_len_raw)
	if length < i + 16 + payload_len_raw then
		return
	end
	subtree:add(payload, buffer(i + 16, payload_len_raw))
	i = i + 16 + payload_len_raw

	local checksum_len = 0
	if checksum_flag_raw > 0 then
		checksum_len = 4
	end
	if length < length - checksum_len - i then
		return
	end
	subtree:add(padding, buffer(i, length - checksum_len - i))
	if checksum_len > 0 then
		subtree:add(checksum, buffer(length - checksum_len, checksum_len))
	else
		subtree:add(checksum, -1)
	end
end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(55001, mgen_protocol)
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(55002, mgen_protocol)
