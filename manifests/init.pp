class lollerskates {

    file { "/usr/local/lollerskates":
      ensure  => directory,
      recurse => true,
      owner   => root,
      group   => root,
      mode    => 755,
      source  => "puppet:///modules/lollerskates"
    }

    file { "/var/lib/lollerskates":
      ensure  => directory,
      owner   => root,
      group   => root,
      mode    => 755,
    }

    cron { lollerskates:
        command => "/usr/local/lollerskates/lollerskates.py",
        user => root,
        minute => '0',
        ensure => present
    }

}
