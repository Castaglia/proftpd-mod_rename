package ProFTPD::Tests::Modules::mod_rename;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use File::Copy;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  rename_stor_prefix => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_suffix => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_filter_regex => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_filter_regex_opt_ignorecase => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_filter_duplicate => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_filter_duplicate_opt_ignorecase => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_enable_off => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_enable_off_ftpaccess => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_prefix_max_count_zero => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  rename_stor_suffix_max_count_zero => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub rename_stor_prefix {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $renamed_file = File::Spec->rel2abs("$tmpdir/1.test.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file = '/private' . $test_file;
        $renamed_file = '/private' . $renamed_file;
      }

      $self->assert(-f $test_file,
        test_msg("File $test_file does not exist as expected"));

      $self->assert(-f $renamed_file,
        test_msg("File $renamed_file does not exist as expected"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_suffix {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$home_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $renamed_file = File::Spec->rel2abs("$tmpdir/test.txt.1");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenameSuffix \".#\"
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file = '/private' . $test_file;
        $renamed_file = '/private' . $renamed_file;
      }

      $self->assert(-f $test_file,
        test_msg("File $test_file does not exist as expected"));

      $self->assert(-f $renamed_file,
        test_msg("File $renamed_file does not exist as expected"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_filter_regex {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file1 = File::Spec->rel2abs("$home_dir/foo.txt");
  if (open(my $fh, "> $test_file1")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file1: $!");
    }

  } else {
    die("Can't open $test_file1: $!");
  }

  my $renamed_file1 = File::Spec->rel2abs("$tmpdir/1.foo.txt");

  my $test_file2 = File::Spec->rel2abs("$home_dir/bar.txt");
  if (open(my $fh, "> $test_file2")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file2: $!");
    }

  } else {
    die("Can't open $test_file2: $!");
  }

  my $renamed_file2 = File::Spec->rel2abs("$tmpdir/1.bar.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
  RenameFilter foo\.
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("foo.txt");
      unless ($conn) {
        die("STOR foo.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw("bar.txt");
      unless ($conn) {
        die("STOR bar.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file1 = '/private' . $test_file1;
        $test_file2 = '/private' . $test_file2;
        $renamed_file1 = '/private' . $renamed_file1;
        $renamed_file2 = '/private' . $renamed_file2;
      }

      $self->assert(-f $test_file1,
        test_msg("File $test_file1 does not exist as expected"));

      $self->assert(-f $renamed_file1,
        test_msg("File $renamed_file1 does not exist as expected"));

      $self->assert(-f $test_file2,
        test_msg("File $test_file2 does not exist as expected"));

      $self->assert(!-f $renamed_file2,
        test_msg("File $renamed_file2 exists unexpectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_filter_regex_opt_ignorecase {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file1 = File::Spec->rel2abs("$home_dir/foo.txt");
  if (open(my $fh, "> $test_file1")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file1: $!");
    }

  } else {
    die("Can't open $test_file1: $!");
  }

  my $renamed_file1 = File::Spec->rel2abs("$tmpdir/1.foo.txt");

  my $test_file2 = File::Spec->rel2abs("$home_dir/bar.txt");
  if (open(my $fh, "> $test_file2")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file2: $!");
    }

  } else {
    die("Can't open $test_file2: $!");
  }

  my $renamed_file2 = File::Spec->rel2abs("$tmpdir/1.bar.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
  RenameFilter FOO\. IgnoreCase
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("foo.txt");
      unless ($conn) {
        die("STOR foo.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw("bar.txt");
      unless ($conn) {
        die("STOR bar.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file1 = '/private' . $test_file1;
        $test_file2 = '/private' . $test_file2;
        $renamed_file1 = '/private' . $renamed_file1;
        $renamed_file2 = '/private' . $renamed_file2;
      }

      $self->assert(-f $test_file1,
        test_msg("File $test_file1 does not exist as expected"));

      $self->assert(-f $renamed_file1,
        test_msg("File $renamed_file1 does not exist as expected"));

      $self->assert(-f $test_file2,
        test_msg("File $test_file2 does not exist as expected"));

      $self->assert(!-f $renamed_file2,
        test_msg("File $renamed_file2 exists unexpectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_filter_duplicate {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file1 = File::Spec->rel2abs("$home_dir/foo.txt");
  if (open(my $fh, "> $test_file1")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file1: $!");
    }

  } else {
    die("Can't open $test_file1: $!");
  }

  my $renamed_file1 = File::Spec->rel2abs("$tmpdir/1.foo.txt");

  my $test_file2 = File::Spec->rel2abs("$home_dir/bar.txt");
  if (open(my $fh, "> $test_file2")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file2: $!");
    }

  } else {
    die("Can't open $test_file2: $!");
  }

  my $renamed_file2 = File::Spec->rel2abs("$tmpdir/1.bar.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
  RenameFilter duplicate
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("foo.txt");
      unless ($conn) {
        die("STOR foo.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw("bar.txt");
      unless ($conn) {
        die("STOR bar.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file1 = '/private' . $test_file1;
        $test_file2 = '/private' . $test_file2;
        $renamed_file1 = '/private' . $renamed_file1;
        $renamed_file2 = '/private' . $renamed_file2;
      }

      $self->assert(-f $test_file1,
        test_msg("File $test_file1 does not exist as expected"));

      $self->assert(-f $renamed_file1,
        test_msg("File $renamed_file1 does not exist as expected"));

      $self->assert(-f $test_file2,
        test_msg("File $test_file2 does not exist as expected"));

      $self->assert(-f $renamed_file2,
        test_msg("File $renamed_file2 does not exist as expected"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_filter_duplicate_opt_ignorecase {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file1 = File::Spec->rel2abs("$home_dir/foo.txt");
  if (open(my $fh, "> $test_file1")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file1: $!");
    }

  } else {
    die("Can't open $test_file1: $!");
  }

  my $renamed_file1 = File::Spec->rel2abs("$tmpdir/1.FOO.txt");

  my $test_file2 = File::Spec->rel2abs("$home_dir/bar.txt");
  if (open(my $fh, "> $test_file2")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file2: $!");
    }

  } else {
    die("Can't open $test_file2: $!");
  }

  my $renamed_file2 = File::Spec->rel2abs("$tmpdir/1.bar.TxT");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
  RenameFilter duplicate IgnoreCase
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("FOO.txt");
      unless ($conn) {
        die("STOR FOO.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $conn = $client->stor_raw("bar.TxT");
      unless ($conn) {
        die("STOR bar.TxT failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      $resp_code = $client->response_code();
      $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file1 = '/private' . $test_file1;
        $test_file2 = '/private' . $test_file2;
        $renamed_file1 = '/private' . $renamed_file1;
        $renamed_file2 = '/private' . $renamed_file2;
      }

      $self->assert(-f $test_file1,
        test_msg("File $test_file1 does not exist as expected"));

      $self->assert(-f $renamed_file1,
        test_msg("File $renamed_file1 does not exist as expected"));

      $self->assert(-f $test_file2,
        test_msg("File $test_file2 does not exist as expected"));

      $self->assert(-f $renamed_file2,
        test_msg("File $renamed_file2 does not exist as expected"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_enable_off {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$home_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $renamed_file = File::Spec->rel2abs("$tmpdir/1.test.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    if ($^O eq 'darwin') {
      # MacOSX hack
      $home_dir = '/private' . $home_dir;
    }

    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
</Directory>

<Directory $home_dir>
  RenameEnable off
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $self->assert(-f $test_file,
        test_msg("File $test_file does not exist as expected"));

      $self->assert(!-f $renamed_file,
        test_msg("File $renamed_file exists unexpectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_enable_off_ftpaccess {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$home_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $renamed_file = File::Spec->rel2abs("$tmpdir/1.test.txt");

  my $ftpaccess_file = File::Spec->rel2abs("$tmpdir/.ftpaccess");
  if (open(my $fh, "> $ftpaccess_file")) {
    print $fh <<EOC;
RenameEnable off
EOC
    unless (close($fh)) {
      die("Can't write $ftpaccess_file: $!");
    }

  } else {
    die("Can't open $ftpaccess_file: $!");
  }

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverride => 'on',
    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\"
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      $self->assert(-f $test_file,
        test_msg("File $test_file does not exist as expected"));

      $self->assert(!-f $renamed_file,
        test_msg("File $renamed_file exists unexpectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_prefix_max_count_zero {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$tmpdir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $renamed_file = File::Spec->rel2abs("$tmpdir/1.test.txt");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenamePrefix \"#.\" max 0
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file = '/private' . $test_file;
        $renamed_file = '/private' . $renamed_file;
      }

      $self->assert(-f $test_file,
        test_msg("File $test_file does not exist as expected"));

      $self->assert(!-f $renamed_file,
        test_msg("File $renamed_file exists unexpectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

sub rename_stor_suffix_max_count_zero {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/rename.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/rename.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/rename.scoreboard");

  my $log_file = test_get_logfile();

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/rename.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/rename.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs($tmpdir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_file = File::Spec->rel2abs("$home_dir/test.txt");
  if (open(my $fh, "> $test_file")) {
    print $fh "Hello, World!\n";
    unless (close($fh)) {
      die("Can't write $test_file: $!");
    }

  } else {
    die("Can't open $test_file: $!");
  }

  my $renamed_file = File::Spec->rel2abs("$tmpdir/test.txt.1");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,

    AuthUserFile => $auth_user_file,
    AuthGroupFile => $auth_group_file,

    AllowOverwrite => 'on',
    AllowStoreRestart => 'on',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_rename.c' => {
        RenameEngine => 'on',
        RenameLog => $log_file,
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<Directory />
  RenameSuffix \".#\" max 0
</Directory>
EOC

    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);

      my $conn = $client->stor_raw("test.txt");
      unless ($conn) {
        die("STOR test.txt failed: " . $client->response_code() . " " .
          $client->response_msg());
      }

      my $buf = "Hello again\n";
      $conn->write($buf, length($buf), 25);
      eval { $conn->close() };

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();
      $self->assert_transfer_ok($resp_code, $resp_msg);

      if ($^O eq 'darwin') {
        # MacOSX hack
        $test_file = '/private' . $test_file;
        $renamed_file = '/private' . $renamed_file;
      }

      $self->assert(-f $test_file,
        test_msg("File $test_file does not exist as expected"));

      $self->assert(!-f $renamed_file,
        test_msg("File $renamed_file exists unexpectedly"));
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    test_append_logfile($log_file, $ex);
    unlink($log_file);

    die($ex);
  }

  unlink($log_file);
}

1;
