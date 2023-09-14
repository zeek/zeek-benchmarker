global tbl: table[count] of count;
global n = 2000000;
global offset = 100000;

event zeek_init()
	{
	local i = offset;
	while ( i < n + offset )
		{
		tbl[i] = i;
		++i;
		}

	local sum = 0;
	for ( [kk], vv in tbl )
		sum += (kk + vv);
	}
