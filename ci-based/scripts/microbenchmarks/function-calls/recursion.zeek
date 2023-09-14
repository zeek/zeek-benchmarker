global n = 500000;

function f(c: count)
	{
	if ( c > 0 )
		f(--c);
	}

event zeek_init()
	{
	local i = n;
	while ( i > 0 )
		{
		f(50);
		--i;
		}
	}
