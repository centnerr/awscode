# Created by Richie Centner
# 02/24/09
#
15 12 * * wed /opt/Scripts/Scans/CIPScans/bin/CIP_cop.pl -a S  2>&1 | mail centnr@pjm.com -s "CIP Cop Scan Completed"
fwl02alp:/opt/Scripts/Scans/CIPScans/bin
# ls CIP_cop.pl
fwl02alp:/opt/Scripts/Scans/CIPScans/bin



# cat CIP_cop.pl
#!/usr/bin/perl -w


use Getopt::Std;
use POSIX 'strftime';
use File::Copy;


$|=1;

our($opt_a,$opt_h);
getopts('ha:');

my $ScanAction = $opt_a;
my $Help =  $opt_h;
my $ScanCount = 0;
my $TotalCount = 0;

die "Usage: CIP_scan.pl [-h] [-a <Action: S {Start Scan}>]\n" if ($Help or (!($ScanAction)));
die "Usage: CIP_scan.pl [-h] [-a <Action: S {Start Scan}>]\n" if ($ScanAction ne 'S');

my $TopDir = "/opt/Scripts/Scans/CIPScans";
my $CIPSubnets = "${TopDir}/CIPSubnets";

my $ScanResults = "${TopDir}/RawScanOut";
my $BinDir = "${TopDir}/bin";
my $InclDir = "${TopDir}/include";
my $Tmp1 = "${TopDir}/tmpout1";
my $LiveHits = "${TopDir}/CIPResults";
my $ArchiveHits = "${TopDir}/OldResults";


my (%IPList,$date,@Targets,$sth,$ScanIt,$sth_ref,$IP,@ScanResults,$Info,$CurrIP,$ScanParams,$RetrOS,$TmpFile);
my $i = 0;
my $Unknown = "Undetermined OS";
my $OS_Holder = "Not Scanned";

my $Scanner = "/usr/bin/nmap";
my $TimeOut = "5000";
my $UnPingable = "Not Pingable";

my $CIPName;
my $Subnet;
my %Subnets;
my @NewHosts;
my $NewHostCnt;
my @LostHosts;
my $LostHostCnt;
my %Archives;
my @DroppedOff;
my @NewlyAdded;

&DataSelect;
&ScanData;
&LoadArchive;
&Compare;
&Notify;

sub DataSelect {
#Archive last run results, so that we have something to compare to
        copy($LiveHits,$ArchiveHits);
# Execute query
        open(INPUTDATA, "${CIPSubnets}") or die "Can't open ${CIPSubnets}:$!\n";
        open(BUILDTMP, ">$Tmp1") or die "Can't open $Tmp1:$!\n";
        while (<INPUTDATA>) {
                /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{2})\|(.*)/;
                $TotalCount++;
                $Subnet = $1;
                $CIPName = $2;
                print BUILDTMP "$Subnet\n";
                $Subnets{$Subnet} = $CIPName;
        }
}

sub ScanData {
        my $CurrSub;
        open(BUILDTMP, "$Tmp1") or die "Can't open $Tmp1:$!\n";
        open(LIVEHIT, ">$LiveHits") or warn "Can't open $LiveHits:$!\n";
        open(RESULTS, ">$ScanResults") or warn "Can't open $ScanResults:$!\n";
        while (<BUILDTMP>) {
                chomp;
                $CurrSub = $_;
                my $HostTimeOut = "2000";
                $ScanParams = "-sP -R --host_timeout $HostTimeOut $CurrSub";
                @ScanResults = qx($Scanner $ScanParams);
                foreach $Info (@ScanResults) {
                chomp ($Info);
                        print RESULTS "$Info\n";
                        if ($Info =~ /Host\s(.*\.pjm\.com)?\s\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\sappears\sto\sbe\sup\./) {
                                $CurrHostname = $1;
                                $CurrIP = $2;
                                $IPList{$CurrIP} = $Info;
                                $ScanCount++;
                                print LIVEHIT "$CurrHostname,$CurrIP,$CurrSub,$Subnets{$CurrSub}\n";
                        } elsif ($Info =~ /Host\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\sappears\sto\sbe\sup\./) {
                                $CurrIP = $1;
                                $IPList{$CurrIP} = $Info;
                                $ScanCount++;
                                print LIVEHIT " ,$CurrIP,$CurrSub,$Subnets{$CurrSub}\n";
                        }

                }
        }
}

sub LoadArchive {
        open(ARCHIVE, "$ArchiveHits") or die "Can't read in $ArchiveHits: $!\n";
        while (<ARCHIVE>) {
                chomp;
                /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
                $ArcIP = $1;
                $ArcEntry = $_;
                $ArcList{$ArcIP} = $ArcEntry;
        }
}

sub Compare {
        while (($ArcKey,$ArcValue) = each(%ArcList)) {
                unless (exists $IPList{$ArcKey}) {
                        push (@DroppedOff, $ArcValue);
                }
        }
        while (($LiveKey,$LiveValue) = each(%IPList)) {
                unless (exists $ArcList{$LiveKey}) {
                        push (@NewlyAdded, $LiveValue);
                }
        }
        $NewHostCnt = @NewlyAdded;
        $LostHostCnt = @DroppedOff;


}
sub DataCompare {

        #
        # List files that are unique to ArchiveHits
        #
        @DroppedOff = qx(/usr/bin/comm -13 $LiveHits $ArchiveHits);

        #
        # List files that are unique to ScanResults
        #
        @NewlyAdded = qx(/usr/bin/comm -23 $LiveHits $ArchiveHits);


        $NewHostCnt = @NewlyAdded;
        $LostHostCnt = @DroppedOff;


}



sub Notify {
        my $Now = scalar localtime();
        my $maildest = 'tripll@pjm.com,centnr@pjm.com,quattf@pjm.com,sweigc@pjm.com';
        #my $maildest = 'centnr@pjm.com';
        open(SENDMAIL, "| /usr/lib/sendmail -t") or die "Couldn't mail to $maildest: $!";
        print SENDMAIL "To: $maildest\nSubject: End of CIP Recon Scan\n\n";
        print SENDMAIL "The recon scan completed $Now\n";
        print SENDMAIL "The total number of new hosts: $NewHostCnt\n";
        print SENDMAIL "The total number of hosts no longer responding: $LostHostCnt\n";
        print SENDMAIL "The total number of hosts: $ScanCount\n";
        if ($NewHostCnt) {
                print SENDMAIL "\nNew hosts:\n";
                foreach $newb (@NewlyAdded) {
                        chomp($newb);
                        print SENDMAIL "$newb\n";
                }
        } if ($LostHostCnt) {
                print SENDMAIL "\nHosts that have dropped off:\n";
                foreach $oldy (@DroppedOff) {
                        chomp($oldy);
                        print SENDMAIL "$oldy\n";
                }
        } if (!$LostHostCnt and !$NewHostCnt) {
                print SENDMAIL "\nAll is quiet\n";
        }
        close SENDMAIL;
}
