<?php

namespace Rat\Engine\Graph;

class Edge
{
    public function __construct(
        public readonly string $from,
        public readonly string $to,
        public readonly string $kind, // CALLS|DISPATCHES|LISTENS_TO|READS|WRITES|TRIGGERS|DEPENDS_ON|AUTHORIZES
        public readonly string $label = '',
        public array $meta = [],
    ) {}

    public function toArray(): array
    {
        return [
            'from' => $this->from,
            'to' => $this->to,
            'kind' => $this->kind,
            'label' => $this->label,
            'meta' => $this->meta,
        ];
    }
}
