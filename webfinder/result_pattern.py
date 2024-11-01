#!/usr/bin/python3
# -*- coding: UTF-8 -*-
from requests import Response
from webfinder.util.tools import Tools


class ResultPattern(object):
    RES_LIMIT = 0.07
    ENTROPY_LIMIT = 0.10
    _status_code = 0
    _length = -1
    _min_length = 0
    _max_length = 0
    _entropy = 0
    _min_entropy = 0
    _max_entropy = 0
    _content_type = None

    def __init__(self,
                 status_code: int = 200,
                 length: int = -1,
                 entropy: float = -1.0,
                 content_type: str = None):
        self._status_code = status_code
        if length > 0:
            self._length = length
            self._min_length = float(self._length) * (1.0 - ResultPattern.RES_LIMIT)
            self._max_length = float(self._length) * (1.0 + ResultPattern.RES_LIMIT)
        if entropy > 0:
            self._entropy = entropy
            self._min_entropy = float(self._entropy) * (1.0 - ResultPattern.ENTROPY_LIMIT)
            self._max_entropy = float(self._entropy) * (1.0 + ResultPattern.ENTROPY_LIMIT)

        if isinstance(content_type, str):
            self._content_type = content_type.lower()

    def is_valid_result(self,
                        status_code: int = 200,
                        length: int = -1,
                        entropy: float = -1.0,
                        content_type: str = None) -> bool:
        from webfinder.config import Configuration

        if status_code != self._status_code:
            return False

        if self._length == -1 or length == -1:
            return True

        if self._min_length <= length <= self._max_length:

            ct = False
            ent = False

            if self._content_type is None or content_type is None or not isinstance(content_type, str):
                ct = True

            if Configuration.no_content_type:
                ct = True

            if ct is False and self._content_type == content_type.lower():
                ct = True

            if self._entropy == -1 or entropy == -1:
                ent = True

            if Configuration.no_entropy:
                ent = True

            if ent is False and self._min_entropy <= entropy <= self._max_entropy:
                ent = True

            if ct is True and ent is True:
                return True

        return False

    def is_valid_response(self, response) -> bool:
        if not isinstance(response, Response):
            return False

        txt = response.content
        entropy = Tools.get_entropy(txt)
        ct = next(iter([
            str(f"{v};").lower().split(';')[0].strip()
            for k, v in response.headers.items()
            if k is not None and k.strip != ''
            and k.lower() == 'content-type'
        ]), None)

        return self.is_valid_result(
            status_code=response.status_code,
            length=len(txt),
            entropy=entropy,
            content_type=ct
        )

    @staticmethod
    def from_response(response):
        if not isinstance(response, Response):
            raise Exception('Invalid response!')

        txt = response.content
        entropy = Tools.get_entropy(txt)
        ct = next(iter([
            str(f"{v};").lower().split(';')[0].strip()
            for k, v in response.headers.items()
            if k is not None and k.strip != ''
            and k.lower() == 'content-type'
        ]), None)

        return ResultPattern(
            status_code=response.status_code,
            length=len(txt),
            entropy=entropy,
            content_type=ct
        )

