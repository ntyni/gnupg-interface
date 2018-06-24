#!/usr/bin/perl -w
#
# $Id: decrypt.t,v 1.4 2001/05/03 06:00:06 ftobin Exp $
#

use strict;
use English qw( -no_match_vars );
use File::Compare;
use version;

use lib './t';
use MyTest;
use MyTestSpecific;

my $compare;

my $gnupg_version = version->parse($gnupg->version);

TEST
{
    reset_handles();

    my $pid = $gnupg->decrypt( handles => $handles );

    print $stdin @{ $texts{encrypted}->data() };
    close $stdin;

    $compare = compare( $texts{plain}->fn(), $stdout );
    close $stdout;
    waitpid $pid, 0;

    if ($gnupg_version < version->parse('2.2.8')) {
        return $CHILD_ERROR == 0;;
    } else {
        local $/ = undef;
        my $errstr = <$stderr>;
        return (($CHILD_ERROR >> 8 == 2) and ($errstr =~ /ignore-mdc-error/));
    }
};


TEST
{
    return $compare == 0;
};


TEST
{
    reset_handles();

    $handles->stdin( $texts{encrypted}->fh() );
    $handles->options( 'stdin' )->{direct} = 1;

    $handles->stdout( $texts{temp}->fh() );
    $handles->options( 'stdout' )->{direct} = 1;

    my $pid = $gnupg->decrypt( handles => $handles );

    waitpid $pid, 0;

    if ($gnupg_version < version->parse('2.2.8')) {
        return $CHILD_ERROR == 0;
    } else {
        local $/ = undef;
        my $errstr = <$stderr>;
        return (($CHILD_ERROR >> 8 == 2) and ($errstr =~ /ignore-mdc-error/));
    }
};


TEST
{
    return compare( $texts{plain}->fn(), $texts{temp}->fn() ) == 0;
};


# test without default_passphrase (that is, by using the agent)
TEST
{
    reset_handles();

    $handles->stdin( $texts{alt_encrypted}->fh() );
    $handles->options( 'stdin' )->{direct} = 1;

    $handles->stdout( $texts{temp}->fh() );
    $handles->options( 'stdout' )->{direct} = 1;

    $gnupg->clear_passphrase();

    my $pid = $gnupg->decrypt( handles => $handles );

    waitpid $pid, 0;

    return $CHILD_ERROR == 0;
};


TEST
{
    return compare( $texts{alt_plain}->fn(), $texts{temp}->fn() ) == 0;
};
