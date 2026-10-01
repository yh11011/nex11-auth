"""Verified release metadata from the existing public GitHub release channel."""
import asyncio
import re
import time

import httpx
from fastapi import APIRouter, HTTPException, Query

router = APIRouter()
REPO = 'yh11011/NexAlarm'
SOURCE = f'https://github.com/{REPO}/releases'
_cache = None
_cached_at = 0.0
_lock = asyncio.Lock()


def validate_release(release, metadata):
    tag = release['tag_name']
    if release.get('draft') or not re.fullmatch(r'v\d+\.\d+\.\d+-beta\.\d+',tag):
        raise ValueError('Not a signed beta release')
    assets = {a['name']:a for a in release.get('assets',[])}
    apk = assets[f'NexAlarm-{tag}.apk']
    expected = f'https://github.com/{REPO}/releases/download/{tag}/{apk["name"]}'
    if apk['browser_download_url'] != expected:
        raise ValueError('Unexpected download source')
    if metadata.get('package_name') != 'com.nexalarm.app' or metadata.get('version_name') != tag[1:]:
        raise ValueError('Package/version mismatch')
    for key in ('version_code','min_sdk','size_bytes'):
        if type(metadata.get(key)) is not int or metadata[key] <= 0:
            raise ValueError('Invalid release metadata')
    if metadata['size_bytes'] != apk['size'] or metadata['size_bytes'] > 200*1024*1024:
        raise ValueError('Invalid size')
    for key in ('sha256','signer_sha256'):
        if not re.fullmatch(r'[a-fA-F0-9]{64}',metadata.get(key,'')):
            raise ValueError('Invalid digest')
    return {k:metadata[k] for k in ('package_name','version_name','version_code','min_sdk','size_bytes','sha256','signer_sha256')} | {
        'available':True,'channel':'beta','apk_url':expected,'release_url':release['html_url'],
        'source_url':SOURCE,'notes':(release.get('body') or '')[:8000],
    }


async def fetch_latest():
    async with httpx.AsyncClient(timeout=10,follow_redirects=True,headers={'Accept':'application/vnd.github+json','User-Agent':'NexAlarm-Updates'}) as client:
        releases = await client.get(f'https://api.github.com/repos/{REPO}/releases',params={'per_page':20})
        releases.raise_for_status()
        for release in releases.json():
            if release.get('draft') or not re.fullmatch(r'v\d+\.\d+\.\d+-beta\.\d+',release.get('tag_name','')):
                continue
            tag=release['tag_name']
            metadata_asset=next((a for a in release['assets'] if a['name']=='update.json'),None)
            if not metadata_asset:
                continue
            expected=f'https://github.com/{REPO}/releases/download/{tag}/update.json'
            if metadata_asset['browser_download_url'] != expected or metadata_asset['size'] > 32768:
                continue
            response = await client.get(expected)
            response.raise_for_status()
            try:
                return validate_release(release,response.json())
            except (ValueError,KeyError,TypeError):
                continue
    return {'available':False,'channel':'beta','source_url':SOURCE,'reason':'No verified compatible release metadata has been published.'}


@router.get('/api/v1/app/releases/latest')
async def latest_release(channel: str = Query(default='beta')):
    if channel != 'beta':
        raise HTTPException(400,'Unsupported update channel')
    global _cache,_cached_at
    async with _lock:
        if _cache is None or time.monotonic()-_cached_at > 300:
            try:
                _cache = await asyncio.wait_for(fetch_latest(),timeout=20)
                _cached_at = time.monotonic()
            except (httpx.HTTPError,ValueError,TimeoutError):
                raise HTTPException(503,'Unable to check updates; try again later')
        return _cache
