<?php

namespace Rat\Engine\Findings;

enum Severity: string
{
    case CRITICAL = 'critical';
    case HIGH = 'high';
    case MEDIUM = 'medium';
    case LOW = 'low';
    case INFO = 'info';

    public function label(): string
    {
        return strtoupper($this->value);
    }

    public function color(): string
    {
        return match ($this) {
            self::CRITICAL => 'red',
            self::HIGH => 'yellow',
            self::MEDIUM => 'cyan',
            self::LOW => 'blue',
            self::INFO => 'gray',
        };
    }

    public function weight(): int
    {
        return match ($this) {
            self::CRITICAL => 100,
            self::HIGH => 75,
            self::MEDIUM => 50,
            self::LOW => 25,
            self::INFO => 10,
        };
    }

    public static function fromString(string $v): self
    {
        return self::tryFrom(strtolower($v)) ?? self::MEDIUM;
    }

    public function meetsThreshold(self $threshold): bool
    {
        return $this->weight() >= $threshold->weight();
    }
}
