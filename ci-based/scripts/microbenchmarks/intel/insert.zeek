# Insert indicators for tracking memory consumption
@load base/frameworks/intel

module Test;

export {
	const num_indicators: count = 0 &redef;
}

event zeek_init()
	{
	local i = 0;
	local meta = Intel::MetaData($source="src");
	local av = vector(0);
	while ( i < num_indicators )
		{
		local a = i % 256;
		local b = (i / 256) % 256;
		local c = (i / 256 / 256) % 256;
		av[0] = (c << 16) | ( b << 8) | a;
		local av_addr = counts_to_addr(av);


		local aitem= Intel::Item($indicator=cat(av_addr), $indicator_type=Intel::ADDR, $meta=meta);
		Intel::insert(aitem);

		local sitem= Intel::Item($indicator=cat(av_addr) + "/32", $indicator_type=Intel::SUBNET, $meta=meta);
		Intel::insert(sitem);

		local user = "user_" + cat(i);
		local uitem= Intel::Item($indicator=user, $indicator_type=Intel::USER_NAME, $meta=meta);
		Intel::insert(uitem);
		++i;
		}
	}
