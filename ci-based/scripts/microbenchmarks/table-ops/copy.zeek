global tbl: table[count] of count;
global n = 4000000;
global offset = 100000;

event zeek_init()
	{
	local i = offset;
	while ( i < n + offset )
		{
		tbl[i] = i;
		++i;
		}

	local tbl2 = copy(tbl);
	print |tbl| + |tbl2|;
	}
