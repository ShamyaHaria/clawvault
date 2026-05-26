'use client'

import { useState } from 'react'
import { Shield, Upload, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'
import Link from 'next/link'

const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:3001'

type Status = 'idle' | 'submitting' | 'success' | 'error'

export default function SubmitPage() {
  const [status, setStatus] = useState<Status>('idle')
  const [submissionId, setSubmissionId] = useState<string>('')
  const [error, setError] = useState<string>('')
  const [file, setFile] = useState<File | null>(null)

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setStatus('submitting')
    setError('')

    const form = e.currentTarget
    const data = new FormData(form)
    if (file) data.set('skill', file)

    try {
      const res = await fetch(`${API_BASE}/api/submissions`, {
        method: 'POST',
        body: data,
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error ?? 'Submission failed')
      }

      const result = await res.json()
      setSubmissionId(result.submissionId)
      setStatus('success')
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Something went wrong')
      setStatus('error')
    }
  }

  if (status === 'success') {
    return (
      <div className="max-w-lg mx-auto text-center py-20">
        <CheckCircle className="w-12 h-12 text-blue-500 mx-auto mb-4" />
        <h1 className="text-2xl font-bold text-white mb-2">Submission received</h1>
        <p className="text-gray-400 mb-6">
          Your skill is being audited. This usually takes under a minute.
        </p>
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-4 mb-6 text-left">
          <p className="text-xs text-gray-500 mb-1">Submission ID</p>
          <p className="font-mono text-sm text-gray-300 break-all">{submissionId}</p>
        </div>
        <div className="flex gap-3 justify-center">
          <Link
            href="/"
            className="border border-gray-700 hover:border-gray-500 text-gray-300 px-5 py-2 rounded-md text-sm transition-colors"
          >
            Back to directory
          </Link>
          <button
            onClick={() => { setStatus('idle'); setSubmissionId(''); setFile(null) }}
            className="bg-blue-600 hover:bg-blue-500 text-white px-5 py-2 rounded-md text-sm transition-colors"
          >
            Submit another
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="max-w-lg mx-auto">
      <div className="mb-8">
        <div className="flex items-center gap-2 mb-2">
          <Shield className="w-5 h-5 text-blue-500" />
          <h1 className="text-xl font-bold text-white">Submit a skill for audit</h1>
        </div>
        <p className="text-gray-400 text-sm">
          Upload your OpenClaw skill as a ZIP file. We'll run it through our 3-layer
          audit pipeline and publish the results publicly.
        </p>
      </div>

      <form onSubmit={handleSubmit} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Skill name</label>
          <input
            name="name"
            required
            placeholder="e.g. file-reader"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Description</label>
          <textarea
            name="description"
            required
            rows={3}
            placeholder="What does this skill do?"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors resize-none"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Author</label>
          <input
            name="author"
            required
            placeholder="Your name or organization"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Repository URL</label>
          <input
            name="repositoryUrl"
            required
            type="url"
            placeholder="https://github.com/you/your-skill"
            className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-600 focus:outline-none focus:border-blue-600 transition-colors"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1.5">Skill ZIP file</label>
          <label className="flex flex-col items-center justify-center w-full border border-dashed border-gray-700 rounded-lg p-8 cursor-pointer hover:border-gray-500 transition-colors bg-gray-900">
            <Upload className="w-6 h-6 text-gray-600 mb-2" />
            {file ? (
              <span className="text-sm text-blue-400">{file.name}</span>
            ) : (
              <>
                <span className="text-sm text-gray-400">Click to upload ZIP</span>
                <span className="text-xs text-gray-600 mt-1">Max 50MB</span>
              </>
            )}
            <input
              type="file"
              accept=".zip"
              className="hidden"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            />
          </label>
        </div>

        {status === 'error' && (
          <div className="flex items-center gap-2 text-red-400 bg-red-950 border border-red-800 rounded-lg px-4 py-3 text-sm">
            <AlertCircle className="w-4 h-4 shrink-0" />
            {error}
          </div>
        )}

        <button
          type="submit"
          disabled={status === 'submitting' || !file}
          className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white py-2.5 rounded-lg font-medium transition-colors flex items-center justify-center gap-2"
        >
          {status === 'submitting' ? (
            <><Loader2 className="w-4 h-4 animate-spin" /> Submitting...</>
          ) : (
            'Submit for audit'
          )}
        </button>

        <p className="text-xs text-gray-600 text-center">
          By submitting you agree that your skill will be publicly audited and the results published.
        </p>
      </form>
    </div>
  )
}