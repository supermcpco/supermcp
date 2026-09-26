import { useEffect, useState } from "react";
import { Button, Dialog, DialogClose, DialogRoot, DialogTitle, DialogTrigger, Text } from "@cloudflare/kumo";
import { List, X } from "@phosphor-icons/react";

/** Where the sidebar stops fitting beside the content (Tailwind's lg). */
const wide = "(min-width: 1024px)";

/**
 * The sidebar on a narrow screen: a top bar with a Menu button that opens
 * the same column as a sheet from the left. The dialog traps focus while
 * it is open, closes on Escape, and hands focus back to the button.
 */
export function Drawer({ children }: { children: (close: () => void) => React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  // Widening the window past the breakpoint brings the sidebar back
  // beside the content; the sheet over it would then be a second copy.
  useEffect(() => {
    const media = window.matchMedia(wide);
    const onChange = () => {
      if (media.matches) setOpen(false);
    };
    media.addEventListener("change", onChange);
    return () => media.removeEventListener("change", onChange);
  }, []);

  return (
    <header className="flex shrink-0 items-center justify-between gap-3 border-b border-kumo-line px-4 py-2 lg:hidden">
      <Text as="span" variant="heading3">
        supermcp
      </Text>
      <DialogRoot open={open} onOpenChange={setOpen}>
        <DialogTrigger
          render={(p) => (
            <Button {...p} variant="secondary" icon={<List aria-hidden />} aria-expanded={open}>
              Menu
            </Button>
          )}
        />
        <Dialog className="top-0 left-0 flex h-full w-72 max-w-[85vw] translate-x-0 flex-col rounded-none sm:top-0 sm:w-72">
          <div className="flex items-center justify-between gap-3 px-5 pt-4">
            <DialogTitle className="sr-only">Menu</DialogTitle>
            <Text as="span" variant="heading3">
              supermcp
            </Text>
            <DialogClose
              render={(p) => (
                <Button {...p} variant="ghost" shape="square" icon={<X aria-hidden />} aria-label="Close menu" />
              )}
            />
          </div>
          {children(close)}
        </Dialog>
      </DialogRoot>
    </header>
  );
}
