<?php

namespace Rat\Engine\Findings;

enum Confidence: string
{
    case HIGH = 'high';
    case MEDIUM = 'medium';
    case LOW = 'low';

    public function label(): string { return strtoupper($this->value); }
}
