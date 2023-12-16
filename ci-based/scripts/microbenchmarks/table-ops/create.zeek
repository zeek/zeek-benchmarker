global tbl: table[count] of count;
global tbl_nested: table[count, count] of table[count] of count;
global n = 5000000;

event zeek_init()
	{
	local i = 0;
	local s = 0;
	while ( i < n )
		{
		tbl = table([i] = i);
		tbl_nested = table([i, i] = table([i] = i));
		tbl_nested[s, s] = table([s] = s);
		s += (|tbl| + |tbl_nested|);
		++i;
		}

	print i, s;
	}
