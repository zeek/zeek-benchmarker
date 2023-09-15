type K: record {
	c1: count;
	c2: count;
};

type V: record {
	c1: count;
	c2: count;
	k0: K &default=K($c1=0, $c2=0);
	k1: K &default=K($c1=1, $c2=1);
	k2: K &default=K($c1=2, $c2=2);
	k3: K &default=K($c1=3, $c2=3);
};

global tbl: table[K] of V;
global n = 2000000;
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
