import { useEffect, useRef } from "react";
import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import { GridComponent, LegendComponent, TooltipComponent } from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { ComposeOption } from "echarts/core";
import type { BarSeriesOption, LineSeriesOption } from "echarts/charts";
import type { GridComponentOption, LegendComponentOption, TooltipComponentOption } from "echarts/components";

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

  useEffect(() => {
    const c = chart.current;
    if (!c || !el.current) return;
    // The canvas cannot read the theme's CSS variables, so it takes the
    // text colour the page has already resolved.
    const color = getComputedStyle(el.current).color;
    c.setOption({ textStyle: { color }, ...option }, { notMerge: true });
  }, [option]);

  return <div ref={el} role="img" aria-label={label} className={className ?? "h-64 w-full"} />;
}
