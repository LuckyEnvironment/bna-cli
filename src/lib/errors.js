// SPDX-License-Identifier: Apache-2.0

/** @typedef {Error & { code?: string }} CodedError */

/**
 * Create an Error with a stable machine-readable classification.
 *
 * @param {string} message
 * @param {string} code
 * @returns {CodedError}
 */
export function codedError(message, code) {
  const error = /** @type {CodedError} */ (new Error(message));
  error.code = code;
  return error;
}

/**
 * @param {unknown} error
 * @returns {CodedError | null}
 */
export function asCodedError(error) {
  return error instanceof Error ? /** @type {CodedError} */ (error) : null;
}

/**
 * @param {unknown} error
 * @returns {string}
 */
export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
