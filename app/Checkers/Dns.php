<?php

namespace App\Checkers;

use Exception;
use App\DnsScan;
use App\Website;
use Badcow\DNS\AlignedBuilder;
use Badcow\DNS\Parser\Parser;
use SebastianBergmann\Diff\Differ;
use Spatie\Dns\Dns as SpatieDns;
use App\Notifications\DnsHasChanged;

class Dns
{
    private $website;

    private $scan;

    public function __construct(Website $website)
    {
        $this->website = $website;
    }

    public function run()
    {
        $this->fetch();
        $this->compare();
        $this->notify();
    }

    private function fetch()
    {
        $dns = SpatieDns::of($this->website->dns_hostname);
        $nameservers = $dns->getRecords('NS');

        preg_match_all('/NS (\S+)$/m', $nameservers, $matches, PREG_SET_ORDER);

        if (count($matches) === 0) {
            return logger()->error('Name servers not found for ' . $this->website->dns_hostname);
        }

        $exception = null;

        foreach ($matches as [, $nameserver]) {
            $nameserver = rtrim($nameserver, '.');

            try {
                $response = $dns->useNameserver($nameserver)->getRecords();
                $exception = null;

                break;
            } catch (Exception $e) {
                $exception = $e;
            }
        }

        if ($exception) {
            return logger()->error($exception->getMessage());
        }

        $zone = Parser::parse($this->website->dns_hostname . '.', $response);

        $scan = new DnsScan([
            'flat' => (new AlignedBuilder())->build($zone),
        ]);

        $this->website->dns()->save($scan);
    }

    private function compare()
    {
        $scans = $this->website->last_dns_scans;

        if ($scans->isEmpty() || $scans->count() === 1) {
            return;
        }

        $diff = (new Differ)->diff(
            $scans->last()->flat,
            $scans->first()->flat
        );

        $placeholder = '--- Original
+++ New
';

        if ($diff === $placeholder) {
            $diff = null;
        }

        $scans->first()->diff = $diff;
        $scans->first()->save();

        $this->scan = $scans->first();
    }

    private function notify()
    {
        if (!$this->scan) {
            return null;
        }

        if (empty($this->scan->diff)) {
            return null;
        }

        $this->website->user->notify(
            new DnsHasChanged($this->website, $this->scan)
        );
    }
}
