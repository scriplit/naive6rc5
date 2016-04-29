use v6;
use Test;
use RC5;

plan 12;

dies-ok {RC5.new()}, "dies when no key specififed";
dies-ok {RC5.new(:key(0x123), :b(1))}, "dies when key too big";
dies-ok {RC5.new(:key(0x12), :w(5))}, "dies with non-x8 word sizes";

my $r = RC5.new(:key(0x0), :w(32), :r(10), :b(10));
is $r.rotate_left( 0xF0000000, 1), 0xE0000001, "Rotate single bit left";
is $r.rotate_right(0x0000000F, 1), 0x80000007, "Rotate single bit right";;
is $r.rotate_left( 0x12345678, 4), 0x23456781, "Rotate bytes left";
is $r.rotate_right(0x12345678, 4), 0x81234567, "Rotate bytes right";

sub checkExample(:$n, :$key, :$a, :$b, :$out1, :$out2) {
    my $r = RC5.new(:$key, :w(32), :b(16), :r(12));
    my $input = sprintf "%x, %x", $a, $b;     
    my $expected_output = $input ~ " -> " ~ sprintf "%x, %x", $out1, $out2;
    my @cy = $r.encrypt($a, $b);
    my $ret = $input ~ sprintf " -> %x, %x", @cy; 
    is $ret, $expected_output, "RC5-32/12/16 - Example $n";
    # say sprintf "DECRYPTED: %x, %x", $r.decrypt(@cy[0], @cy[1]);
}

checkExample(:n(1), :key(0),
             :a(0), :b(0),
             :out1(0xeedba521), :out2(0x6d8f4b15));           

checkExample(:n(2), :key(0x915f4619be41b2516355a50110a9ce91),
             :a(0xeedba521), :b(0x6d8f4b15),
             :out1(0xac13c0f7), :out2(0x52892b5b));
             
checkExample(:n(3), :key(0x783348e75aeb0f2fd7b169bb8dc16787),
             :a(0xac13c0f7), :b(0x52892b5b),
             :out1(0xb7b3422f), :out2(0x92fc6903));
             
checkExample(:n(4), :key(0x915f4619be41b2516355a50110a9ce91),
             :a(0xb7b3422f), :b(0x92fc6903),
             :out1(0xB278C165), :out2(0xCC97D184));
             
checkExample(:n(5), :key(0x5269f149d41ba0152497574d7f153125),
             :a(0xB278C165), :b(0xCC97D184),
             :out1(0x15e444eb), :out2(0x249831da));
             


