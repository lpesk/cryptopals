
from tools.freqanalysis import scoreText, scanKeys, guessKeySize, guessRepXORKey
from tools.message import Message
from tools.randomdata import bddIntegers, randMsg, randPrintableMsg

from hypothesis import assume, given
from hypothesis.strategies import builds, text

sample_english_text = Message("Would you tell me, please, which way I ought to go from here? That depends a good deal on where you want to get to. I don't much care where – Then it doesn't matter which way you go.", 'ascii')

# test that messages generated from printable ascii values score better than random messages, assuming both messages are reasonably long (>= 10 characters)
# this test will fail with small probability so should not be required to pass
@given(rand_msg=builds(randMsg, bddIntegers(min_value=10)), rand_text=builds(randPrintableMsg, bddIntegers(min_value=10)))
def test_scoreText_randTextBeatsRandMsg(rand_msg, rand_text):
    assert scoreText(rand_text) > scoreText(rand_msg)

# test that an english text scores better than a random message generated from printable ascii values
# this test will fail with small probability so should not be required to pass
@given(rand_text=builds(randPrintableMsg, bddIntegers(len(sample_english_text))))
def test_scoreText_englishBeatsRandText(rand_text):
    assert scoreText(sample_english_text) > scoreText(rand_text)
