rod4Proto = Proto("rod4", "ROD4")

tcpTable = DissectorTable.get("tcp.port")

function rod4Proto.dissector(buffer, pinfo, tree)
	start = 0
	subtree = tree:add(rod4Proto, buffer(), string.format("ROD4 Binary Protocol"))

	count = 2
	header = buffer(start, count):uint()
	subtree:add(buffer(start, count), "Header " .. header)
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

	count = 1
	if option2Available then
		subtree:add(buffer(start, count), "Option 2:")
		start = start + count
	end
	if option3Available then
		subtree:add(buffer(start, count), "Option 3:")
		start = start + count
	end

	-- Scan Number -- 
	count  = 8
	scanNumberRaw = buffer(start, count):uint64()
	subtree:add(buffer(start, count), "scan")
	start = start + count

	count = 1
	resolution = buffer(start, count):uint()
	subtree:add(buffer(start, count), "Angular Resolution: " .. resolution)


end

tcpTable:add(9008, rod4Proto)