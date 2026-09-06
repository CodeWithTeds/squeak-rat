<?php

namespace Rat\Engine\Findings;

class Finding
{
    public function __construct(
        public readonly string $id,
        public readonly string $title,
        public readonly string $description,
        public readonly Severity $severity,
        public readonly Confidence $confidence,
        /** @var string e.g. POST /api/import */
        public readonly string $entry,
        /** @var string e.g. $request->file('document') */
        public readonly string $source,
        /** @var string e.g. Storage::put */
        public readonly string $sink,
        /** @var string[] Ordered flow nodes */
        public readonly array $flow,
        /** @var string file path where finding was detected */
        public readonly string $file,
        public readonly int $line,
        /** @var string[] recommendations */
        public readonly array $recommendations = [],
        /** @var string category */
        public readonly string $category = 'data_flow',
        public readonly string $why = '',
    ) {}

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'title' => $this->title,
            'description' => $this->description,
            'severity' => $this->severity->value,
            'confidence' => $this->confidence->value,
            'entry' => $this->entry,
            'source' => $this->source,
            'sink' => $this->sink,
            'flow' => $this->flow,
            'file' => $this->file,
            'line' => $this->line,
            'recommendations' => $this->recommendations,
            'category' => $this->category,
            'why' => $this->why,
        ];
    }
}
