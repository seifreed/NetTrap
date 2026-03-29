# -*- perl -*-
#
# INetSim::Quotd - Base package for Quotd::TCP and Quotd::UDP
#
# (c)2007-2019 Thomas Hungenberg, Matthias Eckert
#
#############################################################

package INetSim::Quotd;

use strict;
use warnings;
use base qw(INetSim::GenericServer);


my $selected_author = undef;
my $selected_quote = undef;


sub select_quote{
    my $serviceName = shift;
    my $quotesfilename = INetSim::Config::getConfigParameter("Quotd_QuotesFileName");
    my $count = 0;
    my $author;
    my $quote;
    my $selected;
    my @authors;
    my @quotes;
    my $line;

    if (! open(FH, $quotesfilename)) {
        # unable to open quotes file
        INetSim::Log::MainLog("Warning: Unable to open quotes file '$quotesfilename': $!.", $serviceName)
    }
    else {
        while ($line=<FH>) {
            chomp($line);
            if ($line !~ /\A\#/){
                my $author = $line;
                my $quote = $line;
                $author =~ s/\A.*\-\-\-(.*)\z/$1/;
                $quote =~ s/\A(.*)\-\-\-.*\z/$1/;
                $author =~ s/\A\s+//;
                $author =~ s/\s+\z//;
                $quote =~ s/\A\s+//;
                $quote =~ s/\s+\z//;
                if (($quote ne "") && ($author ne "")) {
                    push(@authors, $author);
                    push(@quotes, $quote);
                }
            }
            else {
                next;
            }
        }
        close FH;
    }

    if (! scalar @quotes) {
        INetSim::Log::MainLog("Warning: No quotes available. Using built-in dummy quotes instead.", $serviceName);
        # doppelt, wegen rand()
        push(@quotes, "No quotes today :-)");
        push(@quotes, "No quotes today :-)");
        push(@authors, "Matze");
        push(@authors, "Matze");
    }
    $count = @quotes;
    $selected = int(rand($count));
    return ($authors[$selected], $quotes[$selected]);
}


1;
#
