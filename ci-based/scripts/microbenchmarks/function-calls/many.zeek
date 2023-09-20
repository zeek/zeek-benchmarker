global n = 5000000;

function f(c: count): count
	{
	return c;
	}

function fvoid() { }

event zeek_init()
	{
	local i = n;
	local sum = 0;
	while ( i > 0 )
		{
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		sum += f(i);
		fvoid();
		--i;
		}

	print sum;
	}
