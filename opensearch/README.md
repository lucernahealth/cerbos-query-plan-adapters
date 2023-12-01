# Cerbos + OpenSearch Adapter

An adapter library that takes a [Cerbos](https://cerbos.dev) Query Plan ([PlanResources API](https://docs.cerbos.dev/cerbos/latest/api/index.html#resources-query-plan)) response and converts it into a a query for opensearch. This is designed to work alongside a project using the [Cerbos Python SDK](https://github.com/cerbos/cerbos-sdk-python).

The following conditions are supported: `and`, `or`, `not`, `eq`, `ne`, `lt`, `gt`, `le` (`lte`), `ge` (`gte`) and `in`.

## Requirements
- Cerbos > v0.16
- Opensearch

## Usage

```
pip install cerbos-opensearch
```
