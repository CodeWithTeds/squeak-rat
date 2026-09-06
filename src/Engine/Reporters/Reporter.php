<?php

namespace Rat\Engine\Reporters;

use Rat\Engine\Findings\Finding;

interface Reporter
{
    /** @param Finding[] $findings */
    public function report(array $findings, array $stats, array $options = []): string;
}
