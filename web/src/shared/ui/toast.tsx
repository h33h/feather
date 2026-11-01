'use client';
import { useEffect, useRef, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { IconButton } from './components';
const activeDialog = () => document.querySelector<HTMLDialogElement>('dialog[open]');
const serverDialog = () => null;
const subscribeDialogs = (update: () => void) => {
  const observer = new MutationObserver(update);
  observer.observe(document.body, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ['open'],
  });
  return () => observer.disconnect();
};
export function FeedbackIcon() {
  return (
    <svg className="feedback-icon" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
      <circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" strokeWidth="1.8" />
      <path d="M12 7v6m0 3v1" stroke="currentColor" strokeWidth="1.8" />
    </svg>
  );
}
export function Toast({
  message,
  onClose,
  role = 'alert',
}: {
  message: string;
  onClose: () => void;
  role?: 'alert' | 'status';
}) {
  const dialog = useSyncExternalStore(subscribeDialogs, activeDialog, serverDialog);
  const close = useRef(onClose);
  useEffect(() => {
    close.current = onClose;
  }, [onClose]);
  useEffect(() => {
    if (!message) return;
    const timer = setTimeout(() => close.current(), 5000);
    return () => clearTimeout(timer);
  }, [message]);
  if (!message) return null;
  const bubble = (
    <div className="top-toast feedback-bubble" role={role}>
      <FeedbackIcon />
      <span>{message}</span>
      <IconButton tone="ghost" label="Закрыть уведомление" onClick={onClose}>
        <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
          <path d="m6 6 12 12M18 6 6 18" fill="none" stroke="currentColor" strokeWidth="2" />
        </svg>
      </IconButton>
    </div>
  );
  return dialog ? createPortal(bubble, dialog) : bubble;
}
