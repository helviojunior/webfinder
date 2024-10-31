#!/usr/bin/python3
# -*- coding: UTF-8 -*-


class ResultPattern(object):
    RES_LIMIT = 0.07
    _status_code = 0
    _length = -1
    _min_length = 0
    _max_length = 0

    def __init__(self, status_code: int = 200, length: int = -1):
        self._status_code = status_code
        if length > 0:
            self._length = length
            self._min_length = float(self._length) * (1.0 - ResultPattern.RES_LIMIT)
            self._max_length = float(self._length) * (1.0 + ResultPattern.RES_LIMIT)

    def is_valid_result(self, status_code: int = 200, length: int = -1) -> bool:
        if status_code != self._status_code:
            return False

        if self._length == -1 or length == -1:
            return True

        if self._min_length <= length <= self._max_length:
            return True

        return False

