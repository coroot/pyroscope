---
title: Pyroscope and profiling in Grafana
menuTitle: Pyroscope in Grafana
description: Learn about how you can use profile data in Grafana.
weight: 500
keywords:
  - Pyroscope
  - Profiling
  - Grafana
---

<!-- This is placeholder page while we get the content written.  -->

# Pyroscope and profiling in Grafana

Grafana Pyroscope can be used alongside other Grafana products such as Loki, Tempo, Mimir, and k6.
You can use Pyroscope to get the most granular insight into your application and how you can use it to fix issues that you may have identified using metrics, logs, traces, or anything else.

Within Grafana and Grafana Cloud, you can use the [Pyroscope data source](https://grafana.com/docs/grafana/<GRAFANA_VERSION>/datasources/grafana-pyroscope/) to query and visualize profile data from within Grafana.

## Visualize traces and profiles data

Here is a screenshot of the **Explore** page that combines traces and profiles to be able to see granular line-level detail when available for a trace span.
This lets you see the exact function that's causing a bottleneck in your application as well as a specific request.

![trace-profiler-view](https://grafana.com/static/img/pyroscope/pyroscope-trace-profiler-view-2023-11-30.png)

## Integrate profiles into dashboards

Here is an example of how you can integrate profiles into your dashboards. In this case, the screenshot shows memory profiles alongside panels for logs and metrics to be able to debug OOM errors alongside the associated logs and metrics.

![dashboard](https://grafana.com/static/img/pyroscope/grafana-pyroscope-dashboard-2023-11-30.png)
