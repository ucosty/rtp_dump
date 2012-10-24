./rtp_dump test.pcap

for ssrc in `cat $1.payload`; do
	decode-g72x < $ssrc.raw > $ssrc.pcm
	sox -r 8000 -t raw -c 1 -e signed-integer -b 16 $ssrc.pcm $ssrc.wav
	#rm $ssrc.raw $ssrc.pcm
done

sox -m *.wav $1.wav

#for ssrc in `cat $1.payload`; do
#	rm $ssrc.wav
#done
rm $1.payload
unset IFS
