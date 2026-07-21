import { createHash, timingSafeEqual } from 'crypto';
import { RecoveryAnswer, RecoveryQuestion, RecoveryQuestionSet } from './types';

const TOKEN_DOMAIN = 'sat20-wallet-recovery-question-v1';
const MIN_QUESTIONS = 3;
const MAX_QUESTIONS = 8;
const MIN_NORMALIZED_ANSWER_LENGTH = 8;

export function normalizeRecoveryAnswer(answer: string, mode: RecoveryQuestion['normalization'] = 'exact'): string {
  if (typeof answer !== 'string') {
    throw new Error('recovery answer must be a string');
  }

  let normalized = answer
    .normalize('NFKC')
    .replace(/\r\n?/g, '\n')
    .trim()
    .replace(/[\t\n ]+/g, ' ');

  if (mode === 'case-insensitive') {
    normalized = normalized.toLocaleLowerCase('en-US');
  }

  return normalized;
}

function validateAnswers(questionSet: RecoveryQuestionSet, answers: RecoveryAnswer[]): Map<string, string> {
  if (!Array.isArray(answers) || answers.length !== questionSet.questions.length) {
    throw new Error('recovery answers must match the recovery question set');
  }

  const answerMap = new Map<string, string>();
  for (const answer of answers) {
    if (!answer || !answer.questionId || answerMap.has(answer.questionId)) {
      throw new Error('recovery answer question ids must be unique');
    }
    answerMap.set(answer.questionId, answer.answer);
  }

  const normalizedAnswers = new Set<string>();
  for (const question of questionSet.questions) {
    const rawAnswer = answerMap.get(question.id);
    if (rawAnswer === undefined) {
      throw new Error(`missing answer for recovery question ${question.id}`);
    }
    const normalized = normalizeRecoveryAnswer(rawAnswer, question.normalization);
    if (normalized.length < MIN_NORMALIZED_ANSWER_LENGTH) {
      throw new Error(`answer for recovery question ${question.id} is too short`);
    }
    if (normalizedAnswers.has(normalized)) {
      throw new Error('recovery answers must be independent');
    }
    normalizedAnswers.add(normalized);
  }

  return answerMap;
}

export function validateRecoveryQuestionSet(questionSet: RecoveryQuestionSet, answers?: RecoveryAnswer[]) {
  if (!questionSet || questionSet.version !== 1 || !Array.isArray(questionSet.questions)) {
    throw new Error('invalid recovery question set');
  }
  if (questionSet.questions.length < MIN_QUESTIONS || questionSet.questions.length > MAX_QUESTIONS) {
    throw new Error(`recovery question set must contain ${MIN_QUESTIONS}-${MAX_QUESTIONS} questions`);
  }
  if (
    !Number.isInteger(questionSet.requiredAnswers) ||
    questionSet.requiredAnswers < 2 ||
    questionSet.requiredAnswers > questionSet.questions.length
  ) {
    throw new Error('invalid requiredAnswers value');
  }

  const questionIds = new Set<string>();
  for (const question of questionSet.questions) {
    if (!question.id || !question.prompt || question.id.trim().length === 0 || question.prompt.trim().length === 0) {
      throw new Error('recovery questions require an id and prompt');
    }
    if (questionIds.has(question.id)) {
      throw new Error('recovery question ids must be unique');
    }
    questionIds.add(question.id);
  }

  if (answers) validateAnswers(questionSet, answers);
}

export function confirmRecoveryAnswers(
  questionSet: RecoveryQuestionSet,
  firstAnswers: RecoveryAnswer[],
  confirmationAnswers: RecoveryAnswer[]
): void {
  validateRecoveryQuestionSet(questionSet, firstAnswers);
  validateRecoveryQuestionSet(questionSet, confirmationAnswers);

  const firstTokens = createRecoveryAnswerTokens(questionSet, firstAnswers);
  const confirmationTokens = createRecoveryAnswerTokens(questionSet, confirmationAnswers);
  for (let index = 0; index < firstTokens.length; index++) {
    if (!timingSafeEqual(firstTokens[index], confirmationTokens[index])) {
      throw new Error(`recovery answer confirmation does not match question ${questionSet.questions[index].id}`);
    }
  }
}

export function createRecoveryAnswerTokens(
  questionSet: RecoveryQuestionSet,
  answers: RecoveryAnswer[]
): Buffer[] {
  validateRecoveryQuestionSet(questionSet);
  const answerMap = validateAnswers(questionSet, answers);

  return questionSet.questions.map((question) => {
    const normalized = normalizeRecoveryAnswer(answerMap.get(question.id), question.normalization);
    return createHash('sha256')
      .update(TOKEN_DOMAIN, 'utf8')
      .update('\0', 'utf8')
      .update(question.id, 'utf8')
      .update('\0', 'utf8')
      .update(normalized, 'utf8')
      .digest();
  });
}

/**
 * Fuzzy Vault is intentionally abstracted behind a provider. Account-management
 * code never substitutes a password KDF or an ad-hoc vault for a reviewed Fuzzy
 * Vault implementation.
 */
export interface FuzzyVaultProvider {
  lock(secret: Buffer, tokens: Buffer[], requiredTokens: number): Promise<Buffer>;
  unlock(vault: Buffer, tokens: Buffer[]): Promise<Buffer>;
}
