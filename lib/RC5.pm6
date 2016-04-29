use v6;

constant P16 = 0xb7e1;
constant Q16 = 0x9e37;
constant P32 = 0xb7e15163;
constant Q32 = 0x9e3779b9;

class RC5 {
    
    has $!w;   # word size
    has $!r;   # rounds
    has $!b;   # bytes in K  
    has $!key;
    has $!mask;
    has $!u;
    has @!S;
    has @!L;
    has $!c;
    has $!t;
    has Bool $!prepared = False;
    
    submethod BUILD(:$!key, :$!w, :$!r, :$!b) {
        $!w //= 32;
        $!r //= 10;
        $!b //= 16;
        die if ($!w % 8); 
        $!u = $!w div 8;
        die "key must be defined.\n" if !defined $!key;
        die "key must be positive.\n" if $!key < 0;
        die "key too large, check also b.\n" if $!key >= (1 +< ($!b * 8)); 
        die "supported values for w: 16 and 32.\n" if $!w == none(16, 32);
        die "supported values for b: 1..255.\n" if ($!b < 1) || ($!b > 255);
        $!mask = (1 +< $!w) - 1;
        $!c = $!b div $!u;
        $!t = 2 * ($!r + 1);
    }
    
    method prepare() {
        $.convert_key();
        $.init_s();
        $.mixin_k();
        $!prepared = True;
    }
    
    method encrypt($a is copy, $b is copy) {
        $.prepare() if !$!prepared;
        $a = $a + @!S[0];
        $b = $b + @!S[1];
        loop (my $i = 1; $i <= $!r; $i++) {
            $a = ($.rotate_left(($a +^ $b), $b) + @!S[(2 * $i)]) +& $!mask;
            $b = ($.rotate_left(($b +^ $a), $a) + @!S[(2 * $i) + 1]) +& $!mask;
        }
        return $a, $b;
    }

    method decrypt($a is copy, $b is copy) {
        $.prepare() if !$!prepared;
        loop (my $i = $!r; $i <= 1; $i--) {
            $b = $.rotate_right(($b - @!S[2*$i + 1]) +& $!mask, $a) +^ $a;
            $a = $.rotate_right(($a - @!S[2*$i]) +& $!mask, $b) +^ $b;
        }
        $a = $a - @!S[0];
        $b = $b - @!S[1];
        return $a, $b;
    }

    method rotate_left($x, $y is copy) {
        my int $m = $y % $!w;
        my Int $lh = ($x +< $m) +& $!mask;
        my Int $rh = ($x +> ($!w - $m));
        return ($lh +| $rh);
    }

    method rotate_right($x, $y) {
        my int $m = $y % $!w;
        my Int $rh = ($x +> $m) ;
        my Int $lh = ($x +< ($!w - $m)) +& $!mask;
        my $ret = ($lh +| $rh);
        return $ret;
    }
    
    method to_bytes(Int $n is copy) {
        my @bytes;
        my $i = 0;
        while $n > 0 {
            @bytes[$i++] = $n +& 0xFF;
            $n +>= 8;
        }
        return Buf.new(@bytes);
    }
    
    method convert_key() {
        my $K = $.to_bytes($!key);
        loop (my $i = 0; $i < $!c; $i++) {
            @!L[$i] = 0;
        }
        my $j;
        loop ($i = ($!b - 1); $i >= 0; $i--) {
            $j = $i div $!u;
            @!L[$j] = (@!L[$j] +< 8) + $K[$i];
        }
        # say sprintf "@@ key: %x", $!key;
        # say "@@   L: " ~ @!L>>.base(16).join(',');
    }
    
    method init_s() {
        my $q;
        if ($!w == 16) {
            @!S[0] = P16;
            $q = Q16;
        }
        else {
            @!S[0] = P32;
            $q = Q32;
        }
        loop (my $i = 1; $i < $!t; $i++) {
            @!S[$i] = ((@!S[$i - 1] + $q)) +& $!mask;
        }
    }
    
    method mixin_k() {
        my $i = 0;
        my $j = 0;
        my $A = 0;
        my $B = 0;
        my $end = 3 * max($!t, $!c);
        for (^$end) {
            $A = @!S[$i] = $.rotate_left((@!S[$i] + $A + $B) +& $!mask, 3);
            $B = @!L[$j] = $.rotate_left((@!L[$j] + $A + $B) +& $!mask, (($A + $B) +& $!mask));
            $i = ($i + 1) % $!t;
            $j = ($j + 1) % $!c;
        }
        # say "@@  L2: " ~ @!L>>.base(16).join(',');
    }
}

