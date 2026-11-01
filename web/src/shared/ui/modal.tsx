'use client';
import {
  useEffect,
  useId,
  useRef,
  type ReactNode,
  type CSSProperties,
  type RefObject,
} from 'react';
import { DesignAsset, IconButton } from './components';

function focusCurrentHeading() {
  const headings = [
    ...document.querySelectorAll<HTMLElement>(
      'main section[aria-labelledby] > h2, main h2[tabindex]',
    ),
    ...document.querySelectorAll<HTMLElement>('main h1'),
  ];
  const heading = headings.find(
    (element) => !element.closest('[hidden], dialog') && element.getBoundingClientRect().height > 0,
  );
  if (!heading) return;
  if (!heading.hasAttribute('tabindex')) heading.tabIndex = -1;
  heading.focus({ preventScroll: true });
}

function restoreFocus(opener: HTMLElement | null) {
  if (document.querySelector('dialog[open]')) return;
  if (!opener?.isConnected) {
    focusCurrentHeading();
    return;
  }
  if (!opener.matches(':disabled, [aria-disabled="true"]')) {
    opener.focus({ preventScroll: true });
    return;
  }
  // Actions may still be refreshing after the sheet closes. Observe the actual
  // opener until it becomes usable; any new interaction cancels restoration.
  const stop = () => {
    observer.disconnect();
    document.removeEventListener('pointerdown', stop, true);
    document.removeEventListener('keydown', stop, true);
    document.removeEventListener('focusin', cancelOnFocus, true);
  };
  const cancelOnFocus = (event: FocusEvent) => {
    if (event.target !== document.body && event.target !== opener) stop();
  };
  const observer = new MutationObserver(() => {
    if (document.querySelector('dialog[open]')) {
      stop();
      return;
    }
    if (!opener.isConnected) {
      stop();
      focusCurrentHeading();
    } else if (!opener.matches(':disabled, [aria-disabled="true"]')) {
      stop();
      opener.focus({ preventScroll: true });
    }
  });
  observer.observe(document.body, {
    attributes: true,
    attributeFilter: ['disabled', 'aria-disabled', 'open'],
    childList: true,
    subtree: true,
  });
  document.addEventListener('pointerdown', stop, true);
  document.addEventListener('keydown', stop, true);
  document.addEventListener('focusin', cancelOnFocus, true);
}

export function Modal({
  title,
  children,
  onClose,
  width = 393,
  className = '',
  returnFocusRef,
  closeDisabled = false,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  width?: number;
  className?: string;
  returnFocusRef?: RefObject<HTMLElement | null>;
  closeDisabled?: boolean;
}) {
  const dialog = useRef<HTMLDialogElement>(null),
    heading = useId();
  useEffect(() => {
    const element = dialog.current;
    const opener =
      returnFocusRef?.current ??
      (document.activeElement instanceof HTMLElement && document.activeElement !== document.body
        ? document.activeElement
        : null);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    element?.showModal();
    return () => {
      const focus = document.activeElement;
      const shouldRestore = focus === document.body || (focus && element?.contains(focus));
      element?.close();
      document.body.style.overflow = previousOverflow;
      if (shouldRestore) restoreFocus(opener);
    };
  }, [returnFocusRef]);
  return (
    <dialog
      ref={dialog}
      aria-labelledby={heading}
      className={'reference-dialog ui-sheet ' + className}
      style={{ '--dialog-width': width + 'px' } as CSSProperties}
      onCancel={(event) => {
        event.preventDefault();
        if (!closeDisabled) onClose();
      }}
      onClick={(event) => {
        if (closeDisabled || event.target !== event.currentTarget) return;
        const rect = event.currentTarget.getBoundingClientRect();
        if (
          event.clientX < rect.left ||
          event.clientX > rect.right ||
          event.clientY < rect.top ||
          event.clientY > rect.bottom
        )
          onClose();
      }}
    >
      <div className="dialog-heading">
        <h2 id={heading}>{title}</h2>
        <IconButton
          round
          tone="subtle"
          className="dialog-close rounded-close"
          label={'Закрыть: ' + title}
          disabled={closeDisabled}
          onClick={onClose}
        >
          <DesignAsset name="modal-close" />
        </IconButton>
      </div>
      {children}
    </dialog>
  );
}
