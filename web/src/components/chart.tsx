import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { ComposeOption } from "echarts/core";
import type { BarSeriesOption, LineSeriesOption } from "echarts/charts";
import type { GridComponentOption, LegendComponentOption, TooltipComponentOption } from "echarts/components";
import { useColorScheme } from "../lib/color-mode";

// Only the parts of ECharts the screens use, so the rest stays out of the
// bundle. Registering is idempotent, so a second import of this module
// costs nothing.
echarts.use([BarChart, LineChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer]);

export type ChartOption = ComposeOption<
  BarSeriesOption | LineSeriesOption | GridComponentOption | LegendComponentOption | TooltipComponentOption
>;

/**
 * An ECharts canvas. A canvas has no text a screen reader can reach, so
 * the chart is an image with a name, and whatever a person needs from it
 * must also be said in words beside it.
 */
export function Chart({ option, label, className }: { option: ChartOption; label: string; className?: string }) {
  const el = useRef<HTMLDivElement>(null);
  const chart = useRef<echarts.ECharts | null>(null);

  // The chart instance belongs to the element: made when it mounts, gone
  // when it unmounts, resized when it is.
  useEffect(() => {
    if (!el.current) return;
    const c = echarts.init(el.current, undefined, { renderer: "canvas" });
    chart.current = c;
    const resize = new ResizeObserver(() => c.resize());
    resize.observe(el.current);
    return () => {
      resize.disconnect();
      c.dispose();
      chart.current = null;
    };
  }, []);

  // The canvas cannot read the theme's CSS variables, so it takes the
  // colours the page has already resolved for this element's Kumo tokens:
  // text, lines, and the surface a tooltip sits on. ECharts' own defaults
  // are for a white page, and in the dark scheme would draw white grid
  // lines and a white tooltip under light text. It is drawn again when
  // the scheme changes.
  const scheme = useColorScheme();
  useEffect(() => {
    const c = chart.current;
    if (!c || !el.current) return;
    const style = getComputedStyle(el.current);
    const text = style.color;
    const line = style.borderTopColor;
    const axis = {
      axisLine: { lineStyle: { color: line } },
      axisTick: { lineStyle: { color: line } },
      axisLabel: { color: text },
      splitLine: { lineStyle: { color: line } },
    };
    c.setOption({ textStyle: { color: text }, ...option }, { notMerge: true });
    c.setOption({
      ...(option.legend ? { legend: { textStyle: { color: text } } } : {}),
      ...(option.tooltip ? { tooltip: { backgroundColor: style.backgroundColor, borderColor: line, textStyle: { color: text } } } : {}),
      ...(option.xAxis ? { xAxis: axis } : {}),
      ...(option.yAxis ? { yAxis: axis } : {}),
    });
  }, [option, scheme]);

  return (
    <div
      ref={el}
      role="img"
      aria-label={label}
      className={`${className ?? "h-64 w-full"} border-kumo-line bg-kumo-base text-kumo-subtle`}
    />
  );
}
