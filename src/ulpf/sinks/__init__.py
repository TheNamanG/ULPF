"""Output sink abstraction for the ULPF pipeline.

Sinks decouple the pipeline's parsing engine from its output destination.
A new sink is a new class implementing ``BaseSink`` — zero changes to the
pipeline's call sites (Strategy Pattern, per §2).
"""
