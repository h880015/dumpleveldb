#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import io
import glob
import binascii
import varint
import snappy
import builtins as __builtin__

APP_TITLE = "Dump LevelDB"
APP_VERSION = "v1.1"
LDB_FOOTER_BYTES = bytes( [ 0x57, 0xFB, 0x80, 0x8B, 0x24, 0x75, 0x47, 0xDB ] )

LDB_FILE_NAME_GLOB = "*.ldb"
LOG_FILE_NAME_GLOB = "*.log"

IDX_KEY_ST = 0
IDX_KEY_SEQ = 1
IDX_VALUE = 2

gShowMsg = False

def print(*args, **kwargs):
	if gShowMsg:
		return __builtin__.print(*args, **kwargs)

def ParseLogFile( fLog ):
	try:
		with open( fLog, "rb" ) as f:
			logBytes = f.read()
	except Exception as e:
		print( "[E] Can't read file " + fLog + " (" + str( e ) + ")" )
		return None

	print( 'Dump file: ' + fLog )
	print( '' )

	idx = 0
	kvPair = dict()
	while( idx < len( logBytes ) ):
		crcBytes = logBytes[ idx : idx + 4 ]
		size = (logBytes[ idx + 5 ] << 8) + logBytes[ idx + 4 ]
		type = logBytes[ idx + 6 ]
		if type == 1 or type == 2:
			blockBytes = logBytes[ idx + 7 : idx + 7 + size ]
			seq = int.from_bytes( blockBytes[ : 8 ], 'little' )
			count = int.from_bytes( blockBytes[ 8 : (8+4) ], 'little' )
			stream = io.BytesIO( blockBytes[ 12 : ] )
		else:	# elif type == 3 or type == 4:
			stream = io.BytesIO( logBytes[ idx + 7 : idx + 7 + size ] )

		print( 'Log Block at ' + str( idx ) )
		print( '  TYPE = ' + str( type ) + ', SEQ = ' + str( seq ) + ', COUNT = ' + str( count ) )

		for i in range( count ):
			b = stream.read( 1 )
			if len( b ) == 0:
				count = count - i
				break
			st = b[0]
			keyLen = varint.decode_stream( stream )
			keyBytes = stream.read( keyLen )
			if st == 1:
				valLen = varint.decode_stream( stream )
				valBytes = stream.read( valLen )
			else:
				valLen = 0
				valBytes = b'';
			kvPair[ keyBytes ] = [ st, seq, valBytes ]
			seq = seq + 1
			if st == 1:
				print( '    [O] KEY = ' + keyBytes.decode( 'utf-8' ) )
			else:
				print( '    [X] KEY = ' + keyBytes.decode( 'utf-8' ) )
			if len( valBytes ) > 0:
				if valBytes[ 0 ] == 1:
					print( '        VAL = ' + valBytes[ 1 : ].decode( 'utf-8' ) )
				else:
					print( '        VAL = ' + ''.join( '{:02x}'.format(x) for x in valBytes ) )
			else:
				print( '        VAL = <None>' )

		idx = idx + 7 + size
		print( '' )

	return kvPair

def ParseBlock( blockBytes, compressed, crcBytes ):
	if compressed == 1:
		blockBytes = snappy.uncompress( blockBytes )

	kvPair = dict()
	try:
		numRestarts = blockBytes[ -1 ]
		stream2 = io.BytesIO( blockBytes[ : -1 * (1 + 4 * numRestarts) ] )
		bContinue = True
		curKey = ''
		while( bContinue ):
			sharedKeyLen = varint.decode_stream( stream2 )
			inlineKeyLen = varint.decode_stream( stream2 )
			valueLen = varint.decode_stream( stream2 )
			inlineKey = stream2.read( inlineKeyLen )
			valData = stream2.read( valueLen )
			if len( inlineKey ) >=8:
				keyName = inlineKey[ : -8 ]
				keySequence = int.from_bytes( inlineKey[ -7 :  ], 'little' )
				keySt = inlineKey[ -8 ]
				
				if sharedKeyLen != 0:
					curKey = curKey[ : sharedKeyLen ] + keyName
				else:
					curKey = keyName
	
				kvPair[ curKey ] = [ keySt, keySequence, valData ]

				if( keySequence == 0xffffffffffffff ):
					bContinue = False

			if inlineKeyLen == 0 and valueLen == 0:
				bContinue = False

	except Exception as e :
		print( "ParseBlock exception: " + str( e ) )

	return kvPair

def DumpBlock( title, subtitle, kvp, ldbBytes ):
	print( title + ':' )
	kvPair = dict()
	for k in kvp:
		streamVal = io.BytesIO( kvp[ k ][ IDX_VALUE ] )
		loc = varint.decode_stream( streamVal )
		size = varint.decode_stream( streamVal )
		if kvp[ k ][ IDX_KEY_ST ] == 1:
			print( "  [O] KEY = " + k.decode( 'utf-8' ) )
		else:
			print( "  [X] KEY = " + k.decode( 'utf-8' ) )
		print( "      LOC = " + str( loc ) + ", SIZE = " + str( size ) + ", SEQ=" + str( kvp[ k ][ IDX_KEY_SEQ ] ) )

	print( '' )

	for k in kvp:
		streamVal = io.BytesIO( kvp[ k ][ IDX_VALUE ] )
		loc = varint.decode_stream( streamVal )
		size = varint.decode_stream( streamVal )
		print( subtitle + ' at ' + str( loc ) )
		kvpBlock = ParseBlock( ldbBytes[ loc : (loc + size) ], ldbBytes[ loc + size ], ldbBytes[ loc + size : loc + size + 4 ] )
		for blkKey in kvpBlock:
			kvPair[ blkKey ] = kvpBlock[ blkKey ]
			if kvpBlock[ blkKey ][ IDX_KEY_ST ] == 1:
				print( '  [O] KEY = ' + blkKey.decode( 'utf-8' ) )
			else:
				print( '  [X] KEY = ' + blkKey.decode( 'utf-8' ) )
			if len( kvpBlock[ blkKey ][ IDX_VALUE ] ) > 0:
				if kvpBlock[ blkKey ][ IDX_VALUE ][ 0 ] == 1:
					print( '      VAL = ' + kvpBlock[ blkKey ][ IDX_VALUE ][ 1 : ].decode( 'utf-8' ) )
				else:
					print( '      VAL = ' + ''.join( '{:02x}'.format(x) for x in kvpBlock[ blkKey ][ IDX_VALUE ] ) )
			else:
				print( '      VAL = <None>' )
			print( '      SEQ = ' + str( kvpBlock[ blkKey ][ IDX_KEY_SEQ ] ) )

		print( '' )

	return kvPair

def ParseLdbFile( fLdb ):
	try:
		with open( fLdb, "rb" ) as f:
			ldbBytes = f.read()
	except Exception as e:
		print( "[E] Can't read file " + fLdb + " (" + str( e ) + ")" )
		return None

	if ldbBytes[ -8 : ] != LDB_FOOTER_BYTES:
		print( "[E] Not a valid LDB file: can't find footer!" )
		return None

	print( 'Dump file: ' + fLdb )
	print( '' )

	stream = io.BytesIO( ldbBytes[ -48 : ] )
	metaIndexLoc = varint.decode_stream( stream )
	metaIndexSize = varint.decode_stream( stream )
	indexBlockLoc = varint.decode_stream( stream )
	indexBlockSize = varint.decode_stream( stream )

	kvp = ParseBlock( ldbBytes[ metaIndexLoc : (metaIndexLoc + metaIndexSize) ],
		ldbBytes[ metaIndexLoc + metaIndexSize ], ldbBytes[ metaIndexLoc + metaIndexSize : metaIndexLoc + metaIndexSize + 4 ] )

	DumpBlock( 'Meta Index Block', 'Meta Block', kvp, ldbBytes )

	kvp = ParseBlock( ldbBytes[ indexBlockLoc : (indexBlockLoc + indexBlockSize) ],
		ldbBytes[ indexBlockLoc + indexBlockSize ], ldbBytes[ indexBlockLoc + indexBlockSize : indexBlockLoc + indexBlockSize + 4 ] )
	blkkvp = DumpBlock( 'Index Block', 'Data Block', kvp, ldbBytes )

	return blkkvp

def ParseLdbDir( dirLdb ):
	kvCollect = dict()
	kvPair = dict()

	logs = glob.glob( os.path.join( dirLdb, LOG_FILE_NAME_GLOB ) )
	if( len( logs ) == 0 ):
		logs = glob.glob( os.path.join( dirLdb, 'leveldb', LOG_FILE_NAME_GLOB ) )
	for fLog in logs:
		kvp = ParseLogFile( fLog )
		for k in kvp:
			if kvp[ k ][ IDX_KEY_ST ] == 1:
				if k in kvCollect and kvCollect[ k ][ IDX_KEY_SEQ ] > kvp[ k ][ IDX_KEY_SEQ ]:
					continue
				kvCollect[ k ] = kvp[ k ]

	ldbs = glob.glob( os.path.join( dirLdb, LDB_FILE_NAME_GLOB ) )
	if( len( ldbs ) == 0 ):
		ldbs = glob.glob( os.path.join( dirLdb, 'leveldb', LDB_FILE_NAME_GLOB ) )
	for fLdb in ldbs:
		kvp = ParseLdbFile( fLdb )
		for k in kvp:
			if kvp[ k ][ IDX_KEY_ST ] == 1:
				if k in kvCollect and kvCollect[ k ][ IDX_KEY_SEQ ] > kvp[ k ][ IDX_KEY_SEQ ]:
					continue
				kvCollect[ k ] = kvp[ k ]

	for k in kvCollect:
		if len( kvCollect[ k ][ IDX_VALUE ] ) > 0 and kvCollect[ k ][ IDX_VALUE ][0] == 1:
			kvPair[ k.decode( 'utf-8' ) ] = kvCollect[ k ][ IDX_VALUE ][ 1 : ].decode( 'utf-8' );
		else:
			kvPair[ k.decode( 'utf-8' ) ] = kvCollect[ k ][ IDX_VALUE ];

	return kvPair

def dumpleveldbMain():
	print( "" )
	print( APP_TITLE + " " + APP_VERSION )
	print( "" )

	if len( sys.argv ) > 1:
		ParseLdbDir( sys.argv[ 1 ] )
	else:
		print( '' )
		print( 'Usage: python dumpleveldb LEVELDB_DIR' )
		print( '' )

	return 0

if __name__ == '__main__':
	gShowMsg = True
	sys.exit( dumpleveldbMain() )
