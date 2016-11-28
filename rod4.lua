rod4Proto = Proto("rod4", "ROD4")

tcpTable = DissectorTable.get("tcp.port")

function rod4Proto.dissector(buffer, pinfo, tree)
	start = 0
	subtree = tree:add(rod4Proto, buffer(), string.format("ROD4 Binary Protocol"))

	count = 2
	header = buffer(start, count):uint()
	subtree:add(buffer(start, count), string.format("Header: 0x%04x", header))
	start = start + count

	count = 1
	operation = buffer(start, count):uint()

	str = ""
	if operation == 0x23 then
		str = "Measurement values are transferred"
	else
		str = "Invalid"
	end

	subtree:add(buffer(start, count), "Operation: " .. str)
	start = start + count

	count = 1
	option1 = buffer(start, count):uint()

	str = ""
	option2Available = false
	option3Available = false

	if bit.band(option1, 3) > 0 then
		str = str .. "Option 1, Option 2, Option 3, "
		option2Available = true
		option3Available = true
	elseif bit.band(option1, 2) > 0 then
		str = str .. "Option 1, Option 2, "
		option2Available = true
	elseif bit.band(option1, 1) > 0 then
		str = str .. "Option 1 only, "
	end

	if bit.band(option1, 4) > 0 then
		str = str .. "Intialisation"
	elseif bit.band(option1, 8) > 0 then
		str = str .. "Measurement Operation"
	elseif bit.band(option1, 16) > 0 then
		str = str .. "Error"
	end

	subtree:add(buffer(start, count), "Option 1: " .. str)
	start = start + count

	str = ""
	count = 1
	if option2Available then
		option2 = buffer(start, count)
		if option2:bitfield(0) == 1 then
			str = str .. "Field near 1 occupied, "
		end
		if option2:bitfield(1) == 1 then
			str = str .. "Field rar 1 occupied, "
		end
		if option2:bitfield(2) == 1 then
			str = str .. "Warning, "
		end
		if option2:bitfield(3) == 1 then
			str = str .. "Fault, "
		end
		if option2:bitfield(4) == 1 then
			str = str .. "Restart-disable, "
		end
		if option2:bitfield(5) == 1 then
			str = str .. "Field near 2 occupied, "
		end
		if option2:bitfield(6) == 1 then
			str = str .. "Field far 2 occupied, "
		end
		if option2:bitfield(7) == 1 then
			str = str .. "Option byte 3 transferred, "
		end
		str = str:sub(1, -3)
		subtree:add(buffer(start, count), "Option 2: " .. str)
		start = start + count
	end
	if option3Available then
		subtree:add(buffer(start, count), "Option 3:")
		start = start + count
	end

	-- Scan Number -- 
	count  = 8

	scanNumber = 0
	for i=0, 3 do
		byte = buffer(start + i * 2, 1):uint()
		scanNumber = bit.bor(scanNumber, bit.lshift(byte, (3 - i) * 8))
	end
	subtree:add(buffer(start, count), "Scan Number: " .. scanNumber)
	
	start = start + count

	-- Angular Resolution

	count = 1
	resolution = buffer(start, count):uint() * 0.36
	subtree:add(buffer(start, count), "Angular Resolution: " .. resolution)
	start = start + count

	-- Start Angle

	count = 2
	minStartAngle= -5.04
	startAngle = (buffer(start, count):uint() - 1)
	startAngleDeg = startAngle * resolution + minStartAngle
	subtree:add(buffer(start, count), "Start Angle: " .. startAngleDeg)
	start = start + count

	-- Stop Angle
	stopAngle = (buffer(start, count):uint() - 1)
	stopAngleDeg = stopAngle * resolution + minStartAngle
	subtree:add(buffer(start, count), "Stop Angle: " .. stopAngle)
	start = start + count

	-- Calculate number of distance values we expect
	nValues = stopAngle - startAngle + 1
	count = nValues * 2
	distanceTree = subtree:add(buffer(start, count), "Distances : " .. nValues)

	for i=0, nValues-1 do
		count = 2
		bytes = buffer(start, count)
		inNearField = bytes:bitfield(0)
		dist = bit.band(bytes:uint(), 0xFFFE)
		angle = i * resolution + minStartAngle
		distanceTree:add(bytes, string.format("Angle %d, %.2f° : %d mm", i + 1, angle, dist))
		start = start + count
	end
end

tcpTable:add(9008, rod4Proto)