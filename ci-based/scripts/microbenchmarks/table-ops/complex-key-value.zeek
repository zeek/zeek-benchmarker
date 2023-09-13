type K: record {
	c1: count;
	c2: count;
};

type V: record {
	c1: count;
	c2: count;
};

global tbl: table[K] of V;
global n = 1000000;
global offset = 100000;

event zeek_init()
	{
	local i = offset;
	while ( i < n + offset )
		{
		local k = K($c1=i, $c2=i+i);
		local v = V($c1=i, $c2=i+i);
		tbl[k] = v;
		++i;
		}

	local sum = 0;
	for ( [kk], vv in tbl )
		sum += (kk$c1 + kk$c2 + vv$c1 + vv$c2 );
	}
