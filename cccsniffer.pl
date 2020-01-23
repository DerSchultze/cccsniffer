#!/usr/bin/perl

use Device::SerialPort;
use warnings;
use strict;
use Crypt::AuthEnc::GCM;
use Switch;
use IO::File;

$" = '';

my @encryption_key = pack('H*','1234CDEFABCDEF480F49D7');
my @authentication_key = pack('H*','42B1234DABCDEFABCDEFA78E6613FFC821');
my $port = Device::SerialPort->new("/dev/ttyUSB2");
my $outfile = "/usr/local/elmeter/laststat";
my $lockfile = "/tmp/elmeter.lock";

$port->databits(8);
$port->baudrate(2400);
$port->parity("none");
$port->stopbits(1);
$port->read_char_time(30);
$port->read_const_time(1000);


my $lasttime = time();
my @dataarray;
my $index = 0;
my $count = 1;
my $byte = 0;
my @chiper;
my $of;
my $lf;

while(1) {
	$count = 1;
	$index = 0;
	while ($count) {
		($count,$byte)=$port->read(1);
		if ($count) {
			$dataarray[$index++] = $byte;
		}
		# print "Count: $count\n";
	}
	if ($index > 0) {
		# print "Read $index bytes\n";
		$index = scalar(@dataarray);
		# print "Array size $index bytes\n";
		
		my @chiper = @dataarray[11..scalar(@dataarray)-4];
		my @system_title = @chiper[2..2+7];
		my @initialization_vector = (@system_title, @chiper[14..14+3]);
		my @additional_authenticated_data = (@chiper[13..13+0], @authentication_key);
		my @authentication_tag = @chiper[scalar(@chiper)-12..scalar(@chiper)-1];
		my @chiper_text = @chiper[18..scalar(@chiper)-13];

		my $ae = Crypt::AuthEnc::GCM->new("AES", "@encryption_key", "@initialization_vector");	
		$ae->adata_add("@additional_authenticated_data");
		my $pt = $ae->decrypt_add("@chiper_text");

		# print "Data: ".unpack("H*", "@dataarray")."\n";
		# print "Chiper: ".unpack("H*", "@chiper")."\n";
		# print "SystemTitle: ".unpack("H*", "@system_title")."\n";
		# print "IV: ".unpack("H*", "@initialization_vector")."\n";
		# print "AuthTag: ".unpack("H*", "@authentication_tag")."\n";
		# print "Key: ".unpack("H*", "@encryption_key")."\n";
		# print "AddAuthData: ".unpack("H*", "@additional_authenticated_data")."\n\n";

		# print unpack("H*", $pt)."\n\n";
		# print "\033[2J\033[0;0H";
		my @ptr = unpack("C*", $pt);

		# print "$pt\n";


		$count = 0;
		my $outtext = "";
		if (($ptr[0] == 0x0f) && ($ptr[20] == 0x0a)) {
			$outtext = $outtext.sprintf("LongInvokeIdAndPriority\t%06x\n","@ptr[1..4]");
			$outtext = $outtext.sprintf("DateString\t%s\n",unpack ("H*",substr($pt,6,12)));				# todo: Fix output
			$outtext = $outtext.sprintf("Structure Qty\t%02x\n",$ptr[19]);
			$count = 20;
			while ($count < scalar(@ptr)) {
				if ($ptr[$count] == 0x0a) { #string value
					$count++;
					my $length = $ptr[$count++];
					$outtext = $outtext.sprintf("String %d \t%s\n",$length, substr($pt, $count, $length));
					$count += $length;
				}
				if ($ptr[$count] == 0x09) { #obis code
                                        $count++;
                                        my $length = $ptr[$count++];
					$outtext = $outtext.sprintf("%d",$ptr[$count++]);
					for (my $i = 1; $i < $length; $i++) {
						$outtext = $outtext.sprintf(".%d",$ptr[$count++]);
					}
					$outtext = $outtext.sprintf "\t";
					switch ($ptr[$count++]) {
						case 0x06 {			# 32Bit value
							$outtext = $outtext.sprintf("%d", hex(unpack("H*", substr($pt,$count,4))));
							$count += 4;
						}
						case 0x12 {			# 16Bit value
							$outtext = $outtext.sprintf("%d", hex(unpack("H*", substr($pt,$count,2))));
							$count += 2;
						}
						case 0x09 {			# Date Value
                                        		my $length = $ptr[$count++];
							$outtext = $outtext.sprintf("%s", unpack ("H*",substr($pt,$count,$length)));
							$count += $length;
						}
					}
					$outtext = $outtext.sprintf "\n";
					
				}
			}
		}

		open($lf, ">", $lockfile) or die "Cannot open lockfile";
		open($of, ">", $outfile) or die "Cannot open outfile";
		print $of $outtext;
		print $outtext;
		close($lf);
		close($of);
		unlink($lf);
		
	
		select()->flush();
	}
}

		





#select()->flush();
