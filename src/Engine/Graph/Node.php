<?php

namespace Rat\Engine\Graph;

class Node
{
    public function __construct(
        public readonly string $id,
        public readonly string $type, // Route|Controller|Middleware|Service|Model|Job|Event|Listener|Observer|Database|External
        public readonly string $name,
        public readonly string $file = '',
        public readonly int $line = 0,
        public array $meta = [],
    ) {}

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'type' => $this->type,
            'name' => $this->name,
            'file' => $this->file,
            'line' => $this->line,
            'meta' => $this->meta,
        ];
    }
}
